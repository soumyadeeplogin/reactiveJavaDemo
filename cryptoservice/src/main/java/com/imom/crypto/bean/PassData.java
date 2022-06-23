package com.imom.crypto.bean;

public class PassData {
    byte[] passwd;
    byte[] salt;

    public byte[] getPasswd() {
        return passwd;
    }

    public void setPasswd(byte[] passwd) {
        this.passwd = passwd;
    }

    public byte[] getSalt() {
        return salt;
    }

    public void setSalt(byte[] salt) {
        this.salt = salt;
    }

}
