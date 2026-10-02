# libshadow6

`libshadow6` is the deliberately thin local facade for an installed Shadow6.
It delegates feature discovery, policy, credentials, transports, and control to
the installed `shadow6` executable. There is no parallel protocol implementation
or compatibility layer.

```python
from libshadow6 import Shadow6, feature_report

s6 = Shadow6()
print(s6.features())
print(feature_report("go"))
print(s6.call("guide", "--lang", "en"))
```

Set `SHADOW6_CLI` when the installed command is outside `PATH`. The package
fails closed when no installed CLI is available.
