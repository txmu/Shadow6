# libshadow6

`libshadow6` is the deliberately thin local facade for an installed Shadow6.
It delegates feature discovery, policy, credentials, transports, and control to
the installed `shadow6` executable. There is no parallel protocol implementation
or compatibility layer.

```python
from libshadow6 import Shadow6

s6 = Shadow6()
print(s6.features())
print(s6.features("pony"))
print(s6.call("guide", "--lang", "en"))
```

`features()` returns one `shadow6.features.v1` object containing the default
Go, Rust, and Gate reports. `features(component)` returns that component's
report. The facade asks the CLI for its aggregate JSON form; it does not parse
concatenated JSON documents.

`make install` places the package under the selected Python interpreter's
standard `lib/pythonX.Y/site-packages` directory, so `from libshadow6 import
Shadow6` works with that interpreter after installation. Set `SHADOW6_CLI` when
the executable is outside `PATH`. Calls use the instance's executable directly
and do not modify process-global environment variables. The package fails
closed when no installed CLI is available.
