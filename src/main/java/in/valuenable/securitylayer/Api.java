package in.valuenable.securitylayer;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import in.valuenable.securitylayer.utils.Jose;

@RestController
public class Api {

@RequestMapping(value = "/get-illustration/{policyNo}")
public ResponseEntity<String> encrypt(@PathVariable String policyNo) {
    String payload = """
        {
            "policyNumber": "%s",
            "data": "sample data"
        }
        """.formatted(policyNo);
    String encryptedSignedResponse="";
    try {
        encryptedSignedResponse = Jose.jweEncryptAndSign(JoseConstants.DESTINATION_PUBLIC_KEY(), JoseConstants.PRIVATE_KEY(), payload );
    
    } catch (Exception e) {
        System.out.println(e.getMessage());
    }
    return new ResponseEntity<>(encryptedSignedResponse, HttpStatus.OK);
 }

 @RequestMapping(value = "/decrypt/{payload}")
public ResponseEntity<String> decrypt(@PathVariable String payload) {
    String decryptedSignedResponse="";
    try {
        
        decryptedSignedResponse = Jose.jweVerifyAndDecrypt(JoseConstants.DESTINATION_PUBLIC_KEY(), JoseConstants.PRIVATE_KEY(), payload );

    } catch (Exception e) {
        System.out.println(e.getMessage());
    }
    return new ResponseEntity<>(decryptedSignedResponse, HttpStatus.OK);
 }
    
}
