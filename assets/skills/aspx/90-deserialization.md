# .NET deserialization (BinaryFormatter / JSON.NET TypeNameHandling)

Beyond ViewState, any attacker-controlled serialized blob fed to a type-confusing
.NET deserializer is RCE. Hunt for blobs you control in cookies, hidden fields,
query/route params, headers, and uploaded files.

## Sinks to suspect
- `BinaryFormatter.Deserialize`, `SoapFormatter`, `NetDataContractSerializer`,
  `LosFormatter`, `ObjectStateFormatter` — accept polymorphic types ⇒ gadget RCE.
- `JavaScriptSerializer` with a `SimpleTypeResolver`.
- **JSON.NET (Newtonsoft)** with `TypeNameHandling` != `None` ⇒ a `$type`
  property in the JSON picks the runtime type.
- `XmlSerializer` / `DataContractSerializer` with an attacker-supplied type
  name, or `fastJSON` / `FsPickler`.

## Spot the blob
Base64-decode candidates in `browser_evaluate_js` (`atob` + byte helper):
- BinaryFormatter graphs start with bytes `00 01 00 00 00 FF FF FF FF`
  (base64 `AAEAAAD/////...`).
- JSON containing `"$type":"System...."` (e.g.
  `System.Windows.Data.ObjectDataProvider`) ⇒ JSON.NET TypeNameHandling.
- SOAP/XML with `<a:anyType ...>` or a fully-qualified `assembly`/`type` attr.

## Exploit
- JSON.NET: send a gadget like
  `{"$type":"System.Windows.Data.ObjectDataProvider, PresentationFramework",
  "ObjectType":{"$type":"System.Type, mscorlib","TypeName":"System.Diagnostics.Process"},
  "MethodName":"Start","MethodParameters":{...}}` — replay via
  `http_request from_flow` (override the body field), watch for command exec.
- Binary/LOS/OSF sinks: generate the payload with **ysoserial.net**
  (`-f BinaryFormatter|LosFormatter|...`, gadgets `TypeConfuseDelegate`,
  `ObjectDataProvider`, `WindowsIdentity`, `ActivitySurrogateSelector`), base64
  it, and submit it in the same parameter with `http_request`/`http_fuzz`.
  Note: no ysoserial.net in mulot — JSON.NET/`$type` gadgets above are hand-built
  JSON (fully doable here), but BinaryFormatter/LosFormatter/OSF blobs must come
  pre-generated (training data / prior write-up); patch only the command bytes in
  `browser_evaluate_js`. No usable blob ⇒ report as an UNCONFIRMED lead.

Evidence: the gadget payload + command output / OOB callback.
Remediation: don't use `BinaryFormatter` (removed in .NET 7+); JSON.NET
`TypeNameHandling.None`; bind to an allow-list of types with a custom
`SerializationBinder`; `DataContractSerializer` with known types only.
