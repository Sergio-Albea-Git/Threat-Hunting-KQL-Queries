<h1>IOC Collection into MISP</h1>

This Project is  focus on collect IoC that has been already observed into DefenderXDR. Once they are collected using different KQL Queries, they will be added into MISP.

<h3>Requirements</h3>
Azure App Registration with the role ThreatHunting.Read.All.

Key Vault repository with 3 secrets:

  - TenantID
  - AppRegistrationID
  - AppRegistrationSecret

Logic Apps


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

Once the App registration is configured with the required permissions, create a Secret value into the App Registration:

1. Navigate to Certificate & secrets and click on Client secrets --> New client secret:

| <img width="529" height="309" alt="image" src="https://github.com/user-attachments/assets/47b6b754-ee28-4aec-a9d7-3df3ce6ce693" />
|---|

Once is created, save the Value Secret which will be copied into KeyVault in the next step.

<h2>Key Vault</h2>
Create a Key Vault repository into Azure. Navigate to KeyVault services into Azure and create with the default settings. Once is created, navigate inside of it and click on Secrets :

|  <img width="264" height="143" alt="image" src="https://github.com/user-attachments/assets/5e3e38bd-1565-48b3-b635-bf03cf0b9efd" />
|---|

Once there, click on Generate and create the 3 secrets with the saved Secret value and adding the following values which you can find on the Overview page of the created AppRegistration:

- TenantID
- AppID of the App Registration
- Secret Generated on the App Registration

| <img width="444" height="203" alt="image" src="https://github.com/user-attachments/assets/e46d5cf4-17a5-4a1d-8f3b-d0e22105cdad" />
|---|

<h2>Logic Apps</h2>
Once the App Registration is created and the Key Vault is completed with the 3 mentioned secrets, Navigate to Logic Apps inside of Azure and create it using the option Consumption - Multi Tenant and the default values : 

|  <img width="503" height="442" alt="image" src="https://github.com/user-attachments/assets/4b3c0298-7d0a-41c1-9da4-c968d5298013" />
|---|

The next step is give permission to this Logic App for read secrets inside of the created Key Vault. For it, back to the KeyVault repository, select Access Control (IAM) --> Add role assignment:

|  <img width="411" height="167" alt="image" src="https://github.com/user-attachments/assets/aaf93208-ec79-4c99-8cb4-56da4c7a6432" />
|---|

In the Role page, search and select the Key Vault Secret User Role :
|  <img width="723" height="204" alt="image" src="https://github.com/user-attachments/assets/bd937d12-e07b-4949-a3e0-1965570d97c2" /> 
|---|

After it, search the created Logic App selecting Manage Identities and clicking with the option 'Select members' selected:

|  <img width="314" height="216" alt="image" src="https://github.com/user-attachments/assets/0692dec2-55d0-4fdb-a532-bb72ec26fa70" />
|---|

In the new windows, select the created Logic Apps Next and Assign.

Back to the Logic Apps to continue with the last step to create the Logic Apps flow and for this implementation you have import the json available in this repo called  <b> la-ioc-collection-template</b> oriented to collect different IOCS from DefenderXDR and add them into MISP. Navigate into Logic Apps Code View, paste the json content, click on save icon on top.

| <img width="722" height="365" alt="image" src="https://github.com/user-attachments/assets/ebedf535-2e77-418b-b96d-be7a56e24ece" /> 
|---|

After it,navigate to Logic App Designer and a flow should be created on your Logic App. 

The next step is display the Scope action called Token Generation, click on the + icon and select Add an action:

| <img width="271" height="107" alt="image" src="https://github.com/user-attachments/assets/cb138b14-cfbd-4a21-bbce-552a6e87e172" /> 
|---|

In this point, is required to add 3 Key Vault actions which will select the 3 values saved in key vault (repeat the following steps for every secret). 
Search and click for <b>Key Vault Get Secret</b>:

| <img width="298" height="164" alt="image" src="https://github.com/user-attachments/assets/ff299535-780e-4c8d-99e4-f5e436e2568b" /> 
|---|

Once selected, we need to establish the new connection to KeyVault selecting the Autentication Type Managed Identity and writting the name of the created KeyVault Repository, and click on Create New:

| <img width="339" height="322" alt="image" src="https://github.com/user-attachments/assets/ddd9b6bc-88ea-4d69-a0ba-58cc4c374af7" /> 
|---|

and selecting the correspoding value. Rename every action with Get Secret, Get APPID and GET TID. In addition is recommended to secure the inputs and outputs for these secrets values. Select every one of the created Key Vault Actions, click on Setting and navigate under security to enable both options:

| <img width="418" height="431" alt="image" src="https://github.com/user-attachments/assets/ea32d0f9-6cb7-4fc7-8ec3-d41dfe114a7d" /> 
|---|

It should ends like this : 

| <img width="220" height="343" alt="image" src="https://github.com/user-attachments/assets/998efb7a-8fa5-46b1-b75b-c253129de016" /> 
|---|

After it, we need to update the step "HTTP Token" under Token Generation scope replacing the (AppSecretID),(appRegistrationID),(tenantIDValue) for the ones collected by the KeyVault actions. For it, remove the mentioned values, click on the Lighting icon:

| <img width="256" height="47" alt="image" src="https://github.com/user-attachments/assets/1236b06e-09f2-4088-bc26-dd24fc3a711e" />
|---|

and select the corresponding KeyVault value selecting "Value of the secret" for each case:

| <img width="382" height="138" alt="image" src="https://github.com/user-attachments/assets/873f9841-e9f7-4c4f-93fa-eb4842fea7a9" /> 
|---|

it should end like this:

|<img width="336" height="563" alt="image" src="https://github.com/user-attachments/assets/811c782c-a6fe-4660-a716-2991f23841fe" />
|---|

Finally, click on Initialize variables Group and update the MISP URL address and the MISP APIKey with the corresponding values:

| <img width="508" height="563" alt="image" src="https://github.com/user-attachments/assets/688a4b18-9805-4c86-bb44-77f4d8131195" /> 
|---|

Save it, run it and it should start to add the collected IOCs into MISP.


<h2>Others</h2>

Under the FH01 - Email Malware collector, you can modify the step to hide the email subject if contains specific text such as organization name or other sensitive information.
|<img width="556" height="287" alt="image" src="https://github.com/user-attachments/assets/09d7b388-00cb-4c4b-8ee2-a1409f9f69d3" /> 
|---|



