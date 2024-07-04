##Success sign-in from more than 3 countries in one day based on the Latitude and Longitude distance among them##

A while ago, I was annoyed with some Defender XDR alerts related to "User Impossible travel". I had different false positives,
users who were using VPN, different devices, different countries on the same day (not a surprise if you live in central Europe)
and others. So, I decided to create a query to find cases where the user success logins during the same day are from countries 
that are really distant.
The query checks the Longitude and Latitude difference of the first 4 countries, if I have more than 4 countries I will also be
notified. Sorry if there is any error with the calculation, I was (and I am) very bad at math :P 

