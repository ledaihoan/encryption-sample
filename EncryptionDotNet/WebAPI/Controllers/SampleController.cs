using Microsoft.AspNetCore.Mvc;
using System.Text.Json;

namespace WebAPI.Controllers
{
    public class SampleController
    {

        [HttpPost("encrypt-test")]
        public object Payload()
        {
            string originPayload = "{\"data\": \"abc\"}";
            string encrypted = EncryptionHelper.EncryptJsonPayloadWithPublicKeyPemFile("C:\\encryption\\server_public_key.pem", originPayload);
            return JsonSerializer.Deserialize<object>("{\"data\": \"" + encrypted + "\"}");
        }

        [HttpPost("decrypt-test")]
        public object decryptPayload()
        {
            //string encryptedPayload = "sGsMAT1DCKvOCtmENB8ThA==,UMHHKW64314mOsqoLgtwvEYW0mL16kyQNJdQgiZUoUM4SqZyGZlaeVWnzGBYNv/l8BKKSzvopGVHZNfPBY134fOGXiOR2tNrjyifT+MztnDlccx1Dp1zraAnEs0J821MLNBS6+ZwcdyoemAB2krwPlAV7Y+rrQA69g/RsA0bXZ7Kf+m1kkF4vlk+bYfy5IiSmWhYEV9T9PgxG+IAxNcAJSVUMWQK5L3e38KpaWNgeoQLxaaZ+YDM/XeG2W73l4Ax/REfS69YhaQdzqFAaoYB3fSVGodUSop4ARVtSKz1MKGr9BwEPUYZN3xiTcCLwr5RDELMYRm6u09ely5P4Ej1LJh8rB0VKWdyZ53ReCnXs0jkekvx/yi07qSRIocvKn+XZn7mw3VZ3s1n9zleiS97qfUzpshYqFhXyu9TuPL4VHs1TpIoUaysgxcP4p7tAkinhQWu9dZ86ZjzPBDdViPB2c096jSXoHqBZocPqBCjzbBJ2mCldlRAsq0ydS/pk8oLr+6AJoE3cbj3QhbJ2sgaGXlgjze/ZXthRtKHSZAiLJr8XRBpEvSHGvP++54nDr2SSlzCMX4o7MW/hEf1kPPdmK9GsI/5UEIw9U+KRzkgGn7SSPmRNU21Rk0ZtPlBlqGrJCC51qO6tPn6sWdCTP/JiPoJRCbzrhjhjmVykugtCj8=";
            //string decryptedPayload = EncryptionHelper.DecryptJsonPayloadWithPrivateKeyPemFile("C:\\encryption\\server_private_key.pem", encryptedPayload);
            string encryptedPayload = "+Rud5bYO6e0mQYjW+mngj9BE2XQuEjQc2X9WYw5Tc4LNcSzkwS9tce6dY4j4VffjaYYqi7CzWVkTLVBJhR1EOPJ34QzOcXV8/ejU6lYq592MYyAPXnUNtz64CHewri4UDjdBNa7j1zTOdNN/87aHHkR+Lom1nKP4lXDRgbYz8muLffYxIYouWkJ+VR0sh9zMIV96kffDrEWHBVq1myXJtA/Uwqi6W/7ypJ1Rsv5hri7G9wo3fWdLRg9q6crphEH3Mps6orTVqSt2VyrCmrJV3OAUbYBQoDUiJIc0Ld+0A5jVIDAR4rd7DWPO4W+wmljHKZKYEAdmuSD6uNE0iVwvm7pOEyeF+G3Z9XIQ+8sBGDc4Ogn3dg97HvIGWDMuY5w56EPBwvnzJM1BQgTeRbFhbMKt8VUcLvdHecQ0oNngPa9O/KYN1GsFMp9ca0X/Qk7F3yARE0uy3uEcRcL6IylnwsG3lDI2aurC3tjLAp9GUPggspEz6IEgGmFQ7DWQhSqpZJy4ZbAu/ArVDMsqs46czhw+p8ByvSQ5cagHwCEfeda3aSgRFjDfsrOo1+HlzBeYSLizc6O6pxQWrnYPA6X4n6T9V2WLBGYjZG5NsbnEqOEVmbIDLheU9ZLa0lZpMKyzpv+nlioJQfCSI8hnyR2d8y8JftWBXr2V/DbWkkV5hTuVpGVZ0qZ5SgAmzBbDx2pThcFadgNZFy52oyf7vKnjXuSB50JQl6pvn90R9YiDNhbpT1zfGRnkhI4IukMLJyA5ksey8wWOkV3CI8Lg69IjuGDLHzp8CwUw1EnRnCKAeQKCHwg6y2k9Sn/XnaM6tt3N8nui0H/yU5UD/+kuRI7Lg03SrsjujQbCIuMfu/W1dzg/MzMbRNPfG6MUHowetGI9vbGtQ2amYuymjxZO8a0d+5PjL8uZJfDOORaCjT8oLsgp9TiVJeRxiovIAVpu5CkQhdVv5jfAmWKTnZu5i6kjhBV2RRAK9367vbSnR/AARQa4eRsYGBYI56M/933dkPXKKThbWsV2iN4M0MFCYJHLpVX0LlTAg+Sf0ebxIRewUnw=,Q2zfFSAzVPtVjPP9VTK54xfUY0ogsp6hsuGwsJzvHHovVWnZYr7xUURMsrgNg27h3k3FHRxUkgShDEowPF0t+ZNgsq0OBxj2lx+OPD+WdA8DpPQjBK2KwbsSGLTy4AIj1ril1udmyRNrO+lkgVIbuoJP4XafSXHojGMxJ4VsPK3F8xclvCHBOorix9kQTxD4Csd2SzI6T6vA3ZFHu7fVQwzCteFGZiO2C8+uNeJQk7ITBDRcVUOaIWMFBjo2NTtXxVzHTjohNhUcLDrcj7CvQt3+jiMKgQdR/ONDY0qW2UpZl0nMAXI/gKW5ILvmNItDvisTS1bZITc7ltXez8lPrZwm+t8GkfJYqeb0C82h9pl6Z62E3s5J0d2O7At5TcbYEAC1SGnDUcrvK7xf0ptAz9R3VlrKUM84fJ2QJyJCLU4WpQaoFnIbr4Hcb62wNESxN2KDQ3VxhKSvFAyha8gH4GBdwDeH27siTpHULeipSBpb/rSgRWqOpcqiQ42PxKCX9d4HmiEvLuG5Y6bEg+6mP9iTlC+5p4p1ZL7ZDBgqYem9oqHky365P51xTOhUWuTrsySga5v7wYVQatDwk+yaj6sX7/AJPzT6JIKt0kQ7Zj2PpAM9URfMar3uLWfyHQGwFGa/VWZAt+wSR+Ws4yUgmcFgo4vWyNPQlez0wGmjJ5U=";
            string decryptedPayload = EncryptionHelper.DecryptJsonPayloadWithPrivateKeyPemFile("C:\\encryption\\server_private_key.pem", encryptedPayload);
            return JsonSerializer.Deserialize<object>(decryptedPayload);
        }
    }
}
