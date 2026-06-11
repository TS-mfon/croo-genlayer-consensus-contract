# Studionet Deployment

The production caller is a dedicated GenLayer CLI account named `croo-consensus-service`.
Its encrypted keystore remains in the local GenLayer account store. The wallet password
is excluded from Git and must be moved into the worker host's secret manager.

Deployment and live verification artifacts are recorded in `studionet.json`. The file
contains only public addresses and transaction hashes.
