**Classifying Browser Extension by Type and risk severity**

This query is oriented to identify and classify browser extensions by group and risk severity based on a well-known list of browser extension.
```
let Browser_Extension_info = externaldata(browser_extension:string ,metadata_category:string ,metadata_type:string ,metadata_link:string ,metadata_comment:string)[@"https://raw.githubusercontent.com/mthcht/awesome-lists/refs/heads/main/Lists/Browser%20Extensions/browser_extensions_list.csv"] with (format="csv", ignoreFirstRecord=True);
Browser_Extension_info
| join kind= inner (DeviceTvmBrowserExtensions) on $left.browser_extension == $right.ExtensionName
| project metadata_type, Extension_Group= browser_extension, Severity= metadata_link, metadata_comment, DeviceId, ExtensionDescription, ExtensionVersion
```
