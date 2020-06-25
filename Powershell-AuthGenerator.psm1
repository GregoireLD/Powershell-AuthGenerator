<#
.Synopsis
  Generate an 80-bit key, BASE32 encoded, secret
  and a URI to be encoded as a QR code for Google Authenticator compliant applications.
  The QR code can be used with Google Authenticator, BitWarden...
.Example
  # Take a secret code from a real website,
  # but put your own text around it to show in the app
  PS C:\> New-AuthenticatorSecret -UseThisSecretCode HP44SIFI2GFDZHT6 -Name "me@example.com" -Issuer "My bank" -Online | fl *
  Secret    : HP44SIFI2GFDZHT6
  KeyUri    : otpauth://totp/me%40example.com?secret=HP44SIFI2GFDZHT6&issuer=My%20bank%20%F0%9F%92%8E
  # web browser opens, and you can scan your bank code into the app, with new text around it.
#>
function New-AuthenticatorSecret
{
    [CmdletBinding()]
    Param(
        # Secret length in bytes, must be a multiple of 5 bits for neat BASE32 encoding
        # ici 60*8 bits = 480 bits
        [int]
        [ValidateScript({($_ * 8) % 5 -eq 0})]
        $SecretLength = 60,

        # Use an existing secret code, don't generate one, just wrap it with new text
        [string]
        $UseThisSecretCode = '',

        # definis la période de rafraichissement de l'OTP, par défaut 30 secondes
        # les implémentations ne supportent pas forcément le changement de cette valeur
        [ValidateRange(1,120)][int32] $period = 30,
        
        # definis l'algorithme de hashage servant au HMAC, par défaut "SHA1"
        # la norme permet également l'utilisation de "SHA256","SHA512" mais les implémentations ne les supportent pas forcément
        [ValidateSet("SHA1","SHA256","SHA512")][string] $algorithm = "SHA1",

        # definis le nombre de chiffre dans l'OTP résultant, par défaut 6 chiffres
        # la norme permet également l'obtention d'OTP de 8 chiffres
        [ValidateSet(6,8)][int32] $digits = 6,

        # Launches a web browser to show a QR Code
        [switch]
        $Online = $false,


        # Name is text that will appear under the entry in Google Authenticator app, e.g. a login name
        [string] $Name = 'Server:g@duval.paris',


        # Issuer is text that will appear over the entry in Google Authenticator app
        [string] $Issuer = 'Duval Test Server'
    )

    $Script:Base32Charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'

    # if there's a secret provided then use it, otherwise we need to generate one
    if ($PSBoundParameters.ContainsKey('UseThisSecretCode')) {
    
        $Base32Secret = $UseThisSecretCode
    
    } else {

        # Generate random bytes for the secret
        $byteArrayForSecret = [byte[]]::new($SecretLength)
        [Security.Cryptography.RNGCryptoServiceProvider]::new().GetBytes($byteArrayForSecret, 0, $SecretLength)
    

        # BASE32 encode the bytes
        # 5 bits per character doesn't align with 8-bits per byte input,
        # and needs careful code to take some bits from separate bytes.
        # Because we're in a scripting language let's dodge that work.
        # Instead, convert the bytes to a 10100011 style string:
        $byteArrayAsBinaryString = -join $byteArrayForSecret.ForEach{
            [Convert]::ToString($_, 2).PadLeft(8, '0')
        }


        # then use regex to get groups of 5 bits 
        # -> conver those to integer 
        # -> lookup that as an index into the BASE32 character set 
        # -> result string
        $Base32Secret = [regex]::Replace($byteArrayAsBinaryString, '.{5}', {
            param($Match)
            $Script:Base32Charset[[Convert]::ToInt32($Match.Value, 2)]
        })
    }

    # Generate the URI which needs to go to the Google Authenticator App.
    # URI escape each component so the name and issuer can have punctiation characters.
    $otpUri = "otpauth://totp/{0}?secret={1}&issuer={2}&period={3}&algorithm={4}&digits={5}" -f @(
                [Uri]::EscapeDataString($Name),
                $Base32Secret,
                [Uri]::EscapeDataString($Issuer),
                $period,
                $algorithm,
                $digits.ToString()
              )


    # Tidy output
    $keyDetails = [PSCustomObject]@{
        Secret = $Base32Secret
        EnrollURI = $otpUri
        KeyName = [Uri]::EscapeDataString($Name)
        KeyIssuer = [Uri]::EscapeDataString($Issuer)
        KeyPeriod = $period
        KeyAlgorithm = $algorithm
        DigitsSize = $digits
    }

    $keyDetails
}

<#
.Synopsis
  Takes a Google Authenticator secret like 5WYYADYB5DK2BIOV
  and generates the PIN code for it
.Example
  PS C:\>Get-AuthenticatorPin -Secret 5WYYADYB5DK2BIOV
  372 251
#>
function Get-AuthenticatorPin
{
    [CmdletBinding()]
    Param
    (
        # BASE32 encoded Secret e.g. 5WYYADYB5DK2BIOV
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [string] $Secret,

        # definis la période de rafraichissement de l'OTP, par défaut 30 secondes
        # les implémentations ne supportent pas forcément le changement de cette valeur
        [ValidateRange(1,120)][int32] $period = 30,
        
        # definis l'algorithme de hashage servant au HMAC, par défaut "SHA1"
        # la norme permet également l'utilisation de "SHA256","SHA512" mais les implémentations ne les supportent pas forcément
        [ValidateSet("SHA1","SHA256","SHA512")][string] $algorithm = "SHA1",

        # definis le nombre de chiffre dans l'OTP résultant, par défaut 6 chiffres
        # la norme permet également l'obtention d'OTP de 8 chiffres
        [ValidateSet(6,8)][int32] $digits = 6,

        # Indique si la sortie doit éviter d'ajouter l'espace oa milieu du code
        [switch] $MakeSpaceless = $false
    )

    $Script:Base32Charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'

    # Convert the secret from BASE32 to a byte array
    # via a BigInteger so we can use its bit-shifting support,
    # instead of having to handle byte boundaries in code.
    $bigInteger = [Numerics.BigInteger]::Zero
    $cleanSecret = $secret.ToUpper() -replace '[^A-Z2-7]'

    foreach ($char in $cleanSecret.GetEnumerator()) {
        $bigInteger = ($bigInteger -shl 5) -bor ($Script:Base32Charset.IndexOf($char))
    }

    [byte[]]$secretAsBytes = $bigInteger.ToByteArray()
    

    # BigInteger sometimes adds a 0 byte to the end,
    # if the positive number could be mistaken as a two's complement negative number.
    # If it happens, we need to remove it.
    if ($secretAsBytes[-1] -eq 0) {
        $secretAsBytes = $secretAsBytes[0..($secretAsBytes.Count - 2)]
    }


    # BigInteger stores bytes in Little-Endian order, 
    # but we need them in Big-Endian order.
    [array]::Reverse($secretAsBytes)
    

    # Unix epoch time in UTC and divide by the window time,
    # so the PIN won't change for that many seconds
    $epochTime = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    
    # Convert the time to a big-endian byte array
    $timeBytes = [BitConverter]::GetBytes([int64][math]::Floor($epochTime / $period))
    if ([BitConverter]::IsLittleEndian)
    {
        [array]::Reverse($timeBytes) 
    }

    # Perform the HMAC calculation with the specified hash algorithm
    Switch ($algorithm)
    {
        "SHA512" {$hmacGen = [Security.Cryptography.HMACSHA512]::new($secretAsBytes)}
        "SHA256" {$hmacGen = [Security.Cryptography.HMACSHA256]::new($secretAsBytes)}
        default {$hmacGen = [Security.Cryptography.HMACSHA1]::new($secretAsBytes)}
    }

    $hash = $hmacGen.ComputeHash($timeBytes)

    # The hash value's size deprends of the hash algorithm but we want a 6 or 8 digit PIN
    # the TOTP protocol has a calculation to do that
    
    # take half the last byte
    $offset = $hash[$hash.Length-1] -band 0xF

    # use it as an index into the hash bytes and take 4 bytes from there, #
    # big-endian needed
    $fourBytes = $hash[$offset..($offset+3)]
    if ([BitConverter]::IsLittleEndian) {
        [array]::Reverse($fourBytes)
    }

    # Remove the most significant bit
    $num = [BitConverter]::ToInt32($fourBytes, 0) -band 0x7FFFFFFF
    
    # remainder of dividing by 10 to the power of <Numbers of Digits>
    # pad to <Numbers of Digits> digits with leading zero(s)
    # and put a space in the middle for better readability
    [string] $PIN = ($num % ([math]::Pow(10,$digits))).ToString().PadLeft($digits, '0')

    if(-not $MakeSpaceless)
    {
        $PIN = $PIN.Insert($digits/2, ' ')
    }

    $outputPin = [PSCustomObject]@{
        'PINCode' = $PIN
        'SecondsRemaining' = ($period - ($epochTime % $period))
    }

    return $outputPin
}

