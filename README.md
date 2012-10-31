RSA sign 1.0, by Alin Tomescu
tomescu.alin@gmail.com
http://alinush.is-great.org

I wrote this program for fun in a few days, mostly while eating at the local Chipotle in Brooklyn Heights :)

"RSA sign" is an easy to use tool that can digitally sign a piece of text or a file using a given RSA key.

Enjoy!

To build:
=========
```
 $ cd rsasign/src/
 $ make
 $ cd ../bin
 $ rsasign --help
```

To test:
========
 ```
 $ cd rsasign/test/bvt/
 $ make
 $ test-rsasign
 $ cd ../func
 $ ./args.sh
 $ ./func.sh
 $ ./fuzzy.sh
 ```

Use guide:
==========
Pretty straightforword, just look at:
```
 $ rsasign --help
```