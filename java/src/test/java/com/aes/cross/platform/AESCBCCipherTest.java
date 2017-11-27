package com.aes.cross.platform;
import static org.junit.Assert.assertEquals;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

/**
 * Created by Kailash Joshi on 11/26/17.
 */
public class AESCBCCipherTest {

    private AESCBCCipher aes;
    private final String data = "secretData";

    @Before
    public void setup(){
        aes = new AESCBCCipher();
    }

    @Test
    public void encrypt() throws Exception {
        Assert.assertNotNull(aes.encrypt(data));
        Assert.assertNotSame(aes.encrypt(data),"/qcyXf0zZ6WP0EeUfeBdDLpuuLZmjjMPkHkWj0R9enA=");
    }

    @Test
    public void decrypt() throws Exception {
        assertEquals(aes.decrypt("/qcyXf0zZ6WP0EeUfeBdDLpuuLZmjjMPkHkWj0R9enA="),data);
    }




}
