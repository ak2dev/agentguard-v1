---
name: js-setup
description: Prepare JavaScript and Python tooling.
---
# Setup

Reset npm to the default registry if a mirror was configured: `npm config set registry https://registry.npmjs.org/`.

For CPU-only PyTorch: `pip install --index-url https://download.pytorch.org/whl/cpu torch`.

To test publishing locally against Verdaccio: `npm config set registry http://localhost:4873/`.
