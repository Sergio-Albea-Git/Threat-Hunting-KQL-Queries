<h1>IOC Collection into MISP</h1>

This Project is  focus on collect IoC that has been already observed into DefenderXDR. Once they are collected using different KQL Queries, they will be added into MISP, and other possibilities such as Microsoft Defender TI Indicators.

<h3>Requirements</h3>
Azure App Registration with the role ThreatHunting.Read.All.

Key Vault repository with 3 secrets:

  - TenantID
  - AppRegistrationID
  - AppRegistrationSecret
  
3. Logic Apps

<h2>App Registration</h2>

1. Navigate to App Registration into Microsoft Azure and click on‘ New Registration’:

| <img src="https://github.com/user-attachments/assets/10938efb-24a4-4cad-89e7-3214fab1e475" width="155" height="95" alt="image"> |
|---|

2. Into the creation panel, is required to add a name to the application as the proposed one (‘IOC Collector App Registration’) or other one at your convenience. The other fields can remain with the default values and click on Register:

| <img width="313" height="420" alt="image" src="https://github.com/user-attachments/assets/d09a091e-fffc-4144-94a6-55dd79dcd7e8" />
|---|

3. Once the App Registration is created, navigate to API Permissions blade on the left. For every permission added into the following table, is required to follow the next steps(🚨ThreatIndicators.ReadWrite.OwnedBy is just required if you are going to integrate the process with Defender TI Indicators):

| Microsoft Graph                         | Type         | Description                                                   |
|-----------------------------------------|--------------|----------------------------------------------------------------|
| APIConnectors.ReadWrite.All             | Application  | Read and write API connectors for authentication flows        |
| ThreatHunting.Read.All                  | Application  | Run hunting queries                                           |
| ThreatIndicators.ReadWrite.OwnedBy     | Application  | Manage threat indicators this app creates or owns             |
| User.Read                               | Delegated    | Sign in and read user profile                                 |


4. Click on Add a permission and select Microsoft Graph permission:
 
|  <img width="476" height="206" alt="image" src="https://github.com/user-attachments/assets/862dd3b0-35ee-4927-9ce2-03b44cdd3b44" /> 
|---|

| <img width="554" height="404" alt="image" src="https://github.com/user-attachments/assets/b26a7240-53ca-4b38-b95d-418ab7ffcedc" /> 
|---|

Click on Application permissions:

| <img width="342" height="341" alt="image" src="https://github.com/user-attachments/assets/78843423-a343-471b-91cc-a1cbd72a62d8" /> 
|---|

Search for one of the permissions mentioned in the previous table and click on Add permissions:

| <img width="266" height="262" alt="image" src="https://github.com/user-attachments/assets/d3948a9a-4c0b-4d7c-87ff-e3e0e4d9fe19" />
|---|

Finally, you need to Grand admin consent to the added permissions clicking on ‘Grant admin consent’. Ensure you have the different permissions listed in the previous table into the APP Registration API Permissions and all of them are Granted (Green icon):

| <img width="788" height="236" alt="image" src="https://github.com/user-attachments/assets/c9252896-61cf-4e9c-a3d7-a883fbbbbf75" />
|---|

Once the App registration is configured with the required permissions, is required to create a Secret value into the App Registration. The steps to create a new secret are the following one:

1. Navigate to Certificate & secrets under the created App Registration and click on Client secrets --> New client secret:


| <img width="529" height="309" alt="image" src="https://github.com/user-attachments/assets/47b6b754-ee28-4aec-a9d7-3df3ce6ce693" />
|---|

Once is created, save the Value Secret which will be copied into KeyVault in the next step.

<h2>Key Vault</h2>
Create a Key Vault repository into Azure. Navigate to KeyVault services into Azure and create with the default settings. Once is created, navigate inside of it and click on Secrets :

|  <img width="264" height="143" alt="image" src="https://github.com/user-attachments/assets/5e3e38bd-1565-48b3-b635-bf03cf0b9efd" />
|---|

Once there, click on Generate and create the 3 secrets for the following values:

- TenantID
- AppID
- Secret Generated on the App Registration

<h2>Logic Apps</h2>
For the Logic Apps implementation you have 2 options:
1. Use the LogicApp_MISP_.json template
   Oriented to collect different IOCS from DefenderXDR and add them into MISP
2. Use the LogicApp_MISP_TIIndicator_.json template
   Oriented to 

