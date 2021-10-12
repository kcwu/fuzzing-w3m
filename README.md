# w3m fuzzing & issue reproduce

 - some helper scripts and data for fuzzing w3m.
 - fuzzing result and test cases.
 - fuzzing report:
   * [report as 2016](reports/report-2016.html)
   * [recent report](reports/report.html)

Not all test cases are found by me. Please see individual link for their credit.

## Reproduce

Run this first.
```
make init         # will git clone & build dependencies
make build        # build targets
```

### Usage
```
usage: reproduce.py [-h] [--target EXE] [--detector DETECTOR] [--bug]
                    [cases [cases ...]]

positional arguments:
  cases

optional arguments:
  -h, --help           show this help message and exit
  --target EXE         target (w3m executable) to run. [default=all]
  --detector DETECTOR  detectors to run, sample values are
                       none,asan,+m,+m+d,asan+m,msan,ubsan,valgrind,valgrind+m
                       [default=all]
  --bug                produce bug report template
```

### How to generate report
```
./reproduce.py       # by default, run all testcases and generate report.html
```

### How to reproduce crashes with debian's w3m master
 1. sync code manually
 ```
cd targets/w3m-tats
git pull
cd -
```

 2. build variants (asan, msan, ubsan, etc.)
 ```
make do-build-variants T=w3m-tats
```

 3. run
 ```
./reproduce.py --target ./w3m-tats FILE
```

## License
Apache License 2.0. Copyright 2016 Google Inc.

This is not an official Google product.
