"""Manifest of a mutation suite's tree copy; see mutation_snapshot in
scripts/mutation-helpers.sh, the only caller.

    copytracked DIR ROOT LIST    copy the NUL-separated paths of LIST (git
                                 ls-files -z) from ROOT into DIR, one process
    copy DIR ROOT TRACKED WANT   check the fresh copy in DIR against ROOT
                                 (tracked: WANT is the LIST copied)
    seal DIR PREPARE             write DIR.manifest, the stat cache and stamp
    serve                        answer requests, one tab-separated line each:
      reset DIR ROOT             put DIR back to the manifest; value: the count
      report DIR ROOT TRACKED FINAL   ROOT drift; FINAL=1 also resets DIR and
                                 hashes all of it without the stat filter

Content decides: a file's manifest line holds its owner-exec bit, SHA-256 and
size. The stat of a file (lstat: ino, size, mtime_ns, ctime_ns, mode) only
lets a reset skip rereading it: a file whose stat is the one recorded with its
hash is taken as unchanged, unless that stat is within RACY_NS of the stamp
DIR.stamp, written after every record (a write in the same clock tick as the
record leaves the stat as it was). Its mtime is the file system's clock, not
this process's. Every path is walked on every reset, so extra files and
directories are found the same way. Failures print "FAIL mutation ..." and
exit 2 (under serve: answer status 2); paths are printed, contents never.

A suite runs a reset per mutant. A process per reset spent most of its time
starting up, so one serve process per shell answers them all: each answer is
its output lines, then "= STATUS VALUE". It keeps a tree's manifest and stat
cache in memory and reads the cache file again whenever that file is not the
one it last wrote; the stamp is read on every reset. It ends at the end of its
input or when the shell that started it is gone.
"""

import os
import shutil
import stat
import sys

EXCLUDED = {".git", ".gocache", ".gomodcache", ".artifacts", ".lintcache", "__pycache__"}
RACY_NS = 2_000_000_000
hashed = 0
read_buffer = None


class Refused(Exception):
    pass


def fail(message):
    raise Refused(message)


def file_sig(path, st):
    """'X HASH SIZE' of the regular file at path, lstat st taken before reading."""
    import hashlib

    global hashed, read_buffer
    hashed += 1
    # One buffer for every read: a fresh 1 MiB chunk per file cost more than
    # the hash.
    if read_buffer is None:
        read_buffer = bytearray(1 << 20)
    view = memoryview(read_buffer)
    digest = hashlib.sha256()
    size = 0
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        while True:
            n = os.readv(fd, [read_buffer])
            if not n:
                break
            digest.update(view[:n])
            size += n
    finally:
        os.close(fd)
    return ("x" if st.st_mode & stat.S_IXUSR else "-") + " " + digest.hexdigest() + " " + str(size)


def stat_key(st):
    return (st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns, st.st_mode)


def trusted(entry, key, ref_ns):
    """The recorded hash still holds: same stat, recorded outside the racy window."""
    return entry[:5] == key and max(entry[2], entry[3]) < ref_ns - RACY_NS


def entry_line(path, st, cache, ref_ns, stats, rel):
    """The manifest value of one path: ('d',), ('l', target), ('f', sig), ('o',)."""
    if stat.S_ISLNK(st.st_mode):
        return ("l", os.readlink(path))
    if stat.S_ISDIR(st.st_mode):
        return ("d",)
    if stat.S_ISREG(st.st_mode):
        key = stat_key(st)
        entry = cache.get(rel) if cache is not None else None
        if entry is not None and trusted(entry, key, ref_ns):
            sig = entry[5]
        else:
            sig = file_sig(path, st)
        if stats is not None:
            stats[rel] = key + (sig,)
        return ("f", sig)
    return ("o",)


def walk(top, cache=None, ref_ns=0, stats=None):
    """{relative path: value} of every path under top, caches left out."""
    out = {}
    pending = [""]
    while pending:
        rel_dir = pending.pop()
        with os.scandir(os.path.join(top, rel_dir) if rel_dir else top) as entries:
            for item in entries:
                name = item.name
                if name in EXCLUDED:
                    continue
                if "\t" in name or "\n" in name:
                    fail("snapshot: a path name holds a tab or a newline")
                rel = rel_dir + "/" + name if rel_dir else name
                st = item.stat(follow_symlinks=False)
                value = entry_line(item.path, st, cache, ref_ns, stats, rel)
                out[rel] = value
                if value[0] == "d":
                    pending.append(rel)
    return out


def one(top, rel):
    """The value of one path, hashed in full; None when it does not exist."""
    path = os.path.join(top, rel)
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return None
    return entry_line(path, st, None, 0, None, rel)


def write_manifest(path, man):
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        for rel in sorted(man):
            f.write("\t".join((rel,) + man[rel]) + "\n")


def read_manifest(path):
    man = {}
    with open(path, encoding="utf-8", newline="\n") as f:
        for line in f:
            parts = line.rstrip("\n").split("\t")
            man[parts[0]] = tuple(parts[1:])
    return man


class Tree:
    """What serve keeps of one DIR between requests."""

    def __init__(self, d):
        self.man = read_manifest(d + ".manifest")
        self.cache = None
        self.token = None


def write_cache(d, stats, tree=None):
    """The stat cache, then the stamp whose mtime dates it. A token line, then
    a line per file: INO SIZE MTIME_NS CTIME_NS MODE<tab>X HASH SIZE<tab>PATH.
    A helper of another shell may write it too: the token, new on every
    write, tells a helper whether the file is still the one it wrote."""
    token = os.urandom(8).hex()
    with open(d + ".stat", "w", encoding="utf-8", newline="\n") as f:
        f.write(token + "\n")
        for rel, entry in stats.items():
            f.write("%d %d %d %d %d\t%s\t%s\n" % (entry + (rel,)))
    with open(d + ".stamp", "w", encoding="utf-8") as f:
        f.write(token + "\n")
    if tree is not None:
        tree.cache, tree.token = stats, token


def read_cache(d, tree):
    """The stat cache of d and the stamp's mtime, the reference time."""
    with open(d + ".stat", encoding="utf-8", newline="\n") as f:
        token = f.readline().rstrip("\n")
        if tree.cache is None or token != tree.token:
            cache = {}
            for line in f:
                key, sig, rel = line.rstrip("\n").split("\t")
                cache[rel] = tuple(map(int, key.split(" "))) + (sig,)
            tree.cache, tree.token = cache, token
    return tree.cache, os.lstat(d + ".stamp").st_mtime_ns


def source_diff(man, src, skip, tracked):
    """Paths whose line in src (a walk of the source) differs from man."""
    out = []
    for rel, value in man.items():
        if rel in skip:
            continue
        if tracked and value[0] not in ("f", "l"):
            continue
        if src.get(rel) != value:
            out.append(rel)
    if not tracked:
        out.extend(rel for rel in src if rel not in man and rel not in skip)
    return sorted(out)


def read_lines(path):
    try:
        with open(path, encoding="utf-8", newline="\n") as f:
            return {line.rstrip("\n") for line in f if line.strip()}
    except FileNotFoundError:
        return set()


def read_tracked(listing):
    """The exact `git ls-files -z` path list: every record terminated, each
    path unique, relative and free of the manifest's record delimiters."""
    with open(listing, "rb") as f:
        data = f.read()
    if data and not data.endswith(b"\0"):
        fail("snapshot: tracked file list is truncated")
    names = [os.fsdecode(raw) for raw in data.split(b"\0")[:-1]]
    if len(set(names)) != len(names):
        fail("snapshot: duplicate tracked paths")
    for rel in names:
        if any(part in ("", ".", "..") for part in rel.split("/")) or "\t" in rel or "\n" in rel:
            fail("snapshot: unsupported tracked path")
    return names


def cmd_copy_tracked(d, root, listing):
    # One process copies the whole list: `xargs tar -cf -` splits a long list
    # into several archives and the extracting tar stops after the first.
    names = read_tracked(listing)
    for rel in names:
        # A symlinked parent would copy a file from outside ROOT.
        parts = rel.split("/")
        for index in range(1, len(parts)):
            try:
                parent = os.lstat(os.path.join(root, *parts[:index])).st_mode
            except FileNotFoundError:
                fail("snapshot: tracked path " + rel + " is missing from " + root)
            if not stat.S_ISDIR(parent):
                fail("snapshot: tracked path parent is not a directory")
    for rel in names:
        src = os.path.join(root, rel)
        dst = os.path.join(d, rel)
        try:
            st = os.lstat(src)
        except FileNotFoundError:
            fail("snapshot: tracked path " + rel + " is missing from " + root)
        os.makedirs(os.path.dirname(dst) or d, exist_ok=True)
        if stat.S_ISLNK(st.st_mode):
            os.symlink(os.readlink(src), dst)
        elif stat.S_ISREG(st.st_mode):
            shutil.copyfile(src, dst)
            os.chmod(dst, stat.S_IMODE(st.st_mode))
        else:
            fail("snapshot: tracked path " + rel + " is not a file or symlink")


def cmd_copy(d, root, tracked, want):
    copy = walk(d)
    if any(value[0] == "o" for value in copy.values()):
        fail("snapshot: " + root + " holds a path that is not a file, directory or symlink")
    if tracked == "1":
        expected = set(read_tracked(want))
        got = {rel for rel, value in copy.items() if value[0] in ("f", "l")}
        if got != expected:
            fail("snapshot: tracked path set differs (copied %d of %d paths)" % (len(got), len(expected)))
        for rel in expected:
            target_mode = stat.S_IMODE(os.lstat(os.path.join(d, rel)).st_mode)
            source_mode = stat.S_IMODE(os.lstat(os.path.join(root, rel)).st_mode)
            if copy[rel][0] == "f" and target_mode != source_mode:
                fail("snapshot: copied file modes differ")
    drift = source_diff(copy, walk(root), set(), tracked == "1")
    if drift:
        fail("snapshot: the copy differs from %s at %d paths" % (root, len(drift)))
    write_manifest(d + ".copy", copy)


def cmd_seal(d, prepare):
    stats = {}
    man = walk(d, stats=stats)
    pristine = []
    if prepare:
        if any(value[0] == "o" for value in man.values()):
            fail("snapshot: " + prepare + " left a path that is not a file, directory or symlink")
        # Exactly the paths FN changed: its version of each file is the source.
        pristine = source_diff(man, read_manifest(d + ".copy"), set(), False)
        for rel in pristine:
            src = os.path.join(d, rel)
            if man.get(rel, ("",))[0] == "f":
                target = os.path.join(d + ".pristine", rel)
                os.makedirs(os.path.dirname(target), exist_ok=True)
                import shutil

                shutil.copy2(src, target, follow_symlinks=False)
    with open(d + ".pristine.list", "w", encoding="utf-8", newline="\n") as f:
        f.writelines(rel + "\n" for rel in pristine)
    write_cache(d, stats)
    write_manifest(d + ".manifest", man)


def put_file(d, root, rel, sig):
    source = os.path.join(d + ".pristine", rel)
    if not (os.path.isfile(source) and not os.path.islink(source)):
        source = os.path.join(root, rel)
    try:
        st = os.lstat(source)
        ok = stat.S_ISREG(st.st_mode) and file_sig(source, st) == sig
    except OSError:
        ok = False
    if not ok:
        fail("snapshot: source " + rel + " changed during the run")
    target = os.path.join(d, rel)
    with open(source, "rb") as f:
        data = f.read()
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(target, flags, 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    os.chmod(target, stat.S_IMODE(st.st_mode))


def remove(target):
    if os.path.isdir(target) and not os.path.islink(target):
        import shutil

        shutil.rmtree(target)
    else:
        os.unlink(target)


def reset(d, root, tree):
    """Put d back to its manifest; the number of paths touched."""
    man = tree.man
    cache, ref_ns = read_cache(d, tree)
    stats = {}
    before = hashed
    now = walk(d, cache, ref_ns, stats)
    removals = sorted(rel for rel, value in now.items() if rel not in man or man[rel][0] != value[0])
    puts = sorted(rel for rel, value in man.items() if now.get(rel) != value)
    # A step that cannot be done is left to the check below, which names it.
    for rel in removals:
        target = os.path.join(d, rel)
        try:
            if os.path.lexists(target):
                remove(target)
        except OSError:
            pass
    for rel in puts:
        value = man[rel]
        target = os.path.join(d, rel)
        if value[0] not in ("d", "l", "f"):
            fail("snapshot: bad manifest line for " + rel)
        try:
            if value[0] == "d":
                os.makedirs(target, exist_ok=True)
            elif value[0] == "l":
                if os.path.lexists(target):
                    os.unlink(target)
                os.symlink(value[1], target)
            else:
                if os.path.lexists(target):
                    os.unlink(target)
                put_file(d, root, rel, value[1])
        except OSError:
            pass
    touched = sorted(set(removals) | set(puts))
    left = [rel for rel in touched if one(d, rel) != man.get(rel)]
    if left:
        fail("tree reset: %d paths differ" % len(left))
    # Touched paths were hashed again just now: record their new stat. A
    # record, and the stamp that dates it, is written only when a file was
    # hashed: a reset that read no file has nothing new to record.
    for rel in touched:
        stats.pop(rel, None)
        if man.get(rel, ("",))[0] == "f":
            st = os.lstat(os.path.join(d, rel))
            stats[rel] = stat_key(st) + (man[rel][1],)
    if touched or hashed != before:
        write_cache(d, stats, tree)
    return len(touched)


def cmd_report(d, root, tracked, final, tree=None):
    tree = tree or Tree(d)
    man = tree.man
    status = 0
    try:
        src = walk(root)
    except (OSError, Refused):
        print("FAIL mutation snapshot: cannot read " + root)
        src = None
        status = 2
    if src is not None:
        drift = source_diff(man, src, read_lines(d + ".pristine.list"), tracked == "1")
        if drift:
            # Repository paths only, never contents: name what moved under the run.
            print("FAIL mutation snapshot: %s changed during the run, %d paths differ from the snapshot: %s "
                  % (root, len(drift), " ".join(drift[:3])))
            status = 2
    if final == "1" and status == 0:
        if not os.path.isdir(d) or os.path.islink(d):
            fail("snapshot: " + d + " is gone at the end of the run")
        reset(d, root, tree)
        # The stat filter decides nothing here: every file is read once more.
        left = source_diff(man, walk(d), set(), False)
        if left:
            fail("tree reset: final pass: %d paths differ from the manifest: %s"
                 % (len(left), " ".join(left[:3])))
    return status


def answer(trees, args):
    """(status, value) of one serve request; its output goes to stdout."""
    cmd, d = args[0], args[1] if len(args) > 1 else ""
    if cmd == "reset" and len(args) == 3:
        tree = trees.get(d) or trees.setdefault(d, Tree(d))
        return 0, str(reset(d, args[2], tree))
    if cmd == "report" and len(args) == 5:
        return cmd_report(*args[1:], tree=trees.get(d)), ""
    fail("snapshot: bad request " + cmd)


def serve():
    import io
    import select

    parent = os.getppid()
    trees = {}
    pending = b""
    while True:
        while b"\n" not in pending:
            if not select.select([0], [], [], 1.0)[0]:
                if os.getppid() != parent:
                    return 0
                continue
            chunk = os.read(0, 1 << 16)
            if not chunk:
                return 0
            pending += chunk
        line, pending = pending.split(b"\n", 1)
        sys.stdout = io.StringIO()
        value = ""
        try:
            status, value = answer(trees, line.decode("utf-8").split("\t"))
        except Refused as refused:
            print("FAIL mutation " + str(refused))
            status = 2
        except Exception as error:
            # The class only: a message could quote what it read.
            trees.clear()
            print("FAIL mutation snapshot: helper error " + type(error).__name__)
            status = 2
        reply = (sys.stdout.getvalue() + "= %d %s\n" % (status, value)).encode("utf-8")
        sys.stdout = sys.__stdout__
        while reply:
            reply = reply[os.write(1, reply):]


def main(argv):
    cmd, args = argv[1], argv[2:]
    if cmd == "copytracked" and len(args) == 3:
        cmd_copy_tracked(*args)
    elif cmd == "copy":
        cmd_copy(*args)
    elif cmd == "seal":
        cmd_seal(*args)
    elif cmd == "serve" and not args:
        return serve()
    else:
        fail("snapshot: unknown command " + cmd)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except Refused as refused:
        print("FAIL mutation " + str(refused))
        sys.exit(2)
    except Exception as error:
        # A process/filesystem error must fail closed without quoting data.
        print("FAIL mutation snapshot: helper error " + type(error).__name__)
        sys.exit(2)
