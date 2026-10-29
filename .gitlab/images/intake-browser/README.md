# Intake browser CI image

This recipe moves Chromium and Node installation out of each intake job. It does
not change job selection, services, Go module caching, test scripts or mutants.
The Go base and Node archive are pinned; Debian packages are resolved at build
time. Builds are not reproducible from these inputs alone; the published image
digest fixes the runtime contents. Record the final image digest and package
inventory. Chromium security updates require rebuilding and repinning this image.

Build only for linux/amd64 with this directory as context. Validate the image build, Chromium startup and the complete intake job before
promotion. Build, runtime smoke and all three unchanged intake scripts have been
validated locally on linux/amd64, including all77 designated mutants and4 extra
cross-binding checks. The image was published and pulled by its registry digest;
project CI and runner timing acceptance remain separate steps.

The project has no image builder yet. Do not enable privileged runners or DinD.
An unprivileged builder or controlled local builder can publish to this project's registry. In CI use CI_REGISTRY, CI_REGISTRY_IMAGE and
CI_JOB_TOKEN, never embedded credentials. Do not invent a builder image digest.

The child job and its scoped CI contract pin the published registry digest.
Future promotions require a separately built, validated image and reviewed pin change. Never use a mutable tag in
the job and never fall back to apt or downloading Node in the job. A cold image
pull still has a cost; a Go module cache miss still downloads Go modules.
