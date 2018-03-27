Implements [V3](http://github.com/pwsafe/pwsafe/blob/master/docs/formatV3.txt)
format of the https://pwsafe.org.

# Installation

```
git clone github.com/fomichev/pwsf-ruby
```

# Usage example

```
$ echo bogus12345 | ./bin/pwsf -S -p ./simple.psafe3 list

$ echo bogus12345 | ./bin/pwsf -S -p ./simple.psafe3 show "(Four|Five)"

$ ./bin/pwsf -p ./simple.psafe3 copy "(Four|Five)"
```
