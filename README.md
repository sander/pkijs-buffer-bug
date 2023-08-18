# Signature validation bug in PKI.js when using Buffer

To run:

    npm install
    npm test

On my machine with Node.js v20.3.1 this leads to:

     FAIL  src/index.test.js
      ✓ leaf certificate first, not using Buffer (29 ms)
      ✓ leaf certificate not first, not using Buffer (4 ms)
      ✓ leaf certificate first, using Buffer (10 ms)
      ✕ leaf certificate not first, using Buffer (10 ms)
