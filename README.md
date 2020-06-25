# Powershell-AuthGenerator

Powershell Implementation of Google Authenticator Protocol

This implementation was inspired by HumanEquivalentUnit implementation :
https://github.com/HumanEquivalentUnit

To use this module, the "Powershell-AuthGenerator" folder, contaning both the psm1
and the psd1 files, must be in one of your default Powershell Modules folder.
You can check what they are using :
`$env:PSModulePath`

Otherwise, you can manually enable it using the folowing command :

`Import-Module <Path_to_the_Powershell-AuthGenerator.psm1_file>`

# Command list :

**New-AuthenticatorSecret**

Generate a new Authenticator secret

`New-AuthenticatorSecret`

**Get-AuthenticatorPin**

Output the current code from a given secret

`Get-AuthenticatorPin`
