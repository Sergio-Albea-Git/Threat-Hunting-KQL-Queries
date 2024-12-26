**Detect WordPress plugins from HTTP requests**

One of the ongoing threats that I feel we face daily is the use of multiple plugins and add-ons across various sites from devices so I focus on identifying common platforms where users might connect and utilize different features. I started with WordPress plugins to gather information and monitor user activity, particularly to stay informed about any connections to specific WordPress sites that employ unknown plugins.

Additionally, if you have installed a WordPress site on any of your devices and it is integrated with Microsoft Defender for Endpoint, this query can be adapted to detect the plugins in use by the users connectives —both from within and externally. It can also help identify potential attacks and vulnerabilities, such as outdated plugin versions.

```
DeviceNetworkEvents
| where RemoteUrl contains "/wp-content/plugins/"
| extend PluginName = extract(@"/wp-content/plugins/([^/]+)/", 1, RemoteUrl)
| extend Version = extract(@"\?ver=([\d\.]+)$", 1, RemoteUrl)
| extend PluginSiteName = strcat("https://wordpress.org/plugins/", PluginName)
| project PluginSiteName,PluginName,Version, DeviceName, Timestamp,RemoteIPCountry= tostring(geo_info_from_ip_address(RemoteIP).country), ActionType, RemoteUrl

```
