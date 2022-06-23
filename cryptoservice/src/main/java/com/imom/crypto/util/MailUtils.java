package com.imom.crypto.util;

import org.apache.log4j.Logger;
import org.json.JSONObject;

import javax.mail.*;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;
import java.util.Properties;

public class MailUtils {
    private static final Logger logger = Logger.getLogger(MailUtils.class.getName());

    public static void sendSimpleEmail(String username, String passwd, String mailId, String smtpHost, String smtpPort, String smtpAuth, String smtpEnable, JSONObject body) {
        try {

            String email = username;
            String password = passwd;
            String toEmail = mailId;

            logger.info("TLSEmail Start");

            Properties props = new Properties();
            props.put("mail.smtp.host", smtpHost); //SMTP Host
            props.put("mail.smtp.port", smtpPort); //TLS Port
            props.put("mail.smtp.auth", smtpAuth); //enable authentication
            props.put("mail.smtp.starttls.enable", smtpEnable);

            Authenticator auth = new Authenticator() {
                //override the getPasswordAuthentication method
                @Override
                protected PasswordAuthentication getPasswordAuthentication() {
                    return new PasswordAuthentication(email, password);
                }
            };

            Session session = Session.getInstance(props, auth);
            MimeMessage message = new MimeMessage(session);
            message.setFrom(new InternetAddress(toEmail));
            message.addRecipients(Message.RecipientType.TO, toEmail);

            message.setSubject("Crypto-passwords");
            BodyPart messageBodyPart = new MimeBodyPart();

            StringBuilder totalMessage = new StringBuilder();
            totalMessage.append("<body><html>");
            totalMessage.append("Hi team, <br/><br/>");
            totalMessage.append("<p>Please find below password and salt for crypto-service.</p>");
            totalMessage.append(body);
            totalMessage.append("<br/><br/>Thanks, <br/>");
            totalMessage.append("DEC Team </body></html>");
            messageBodyPart.setContent(totalMessage.toString(), "text/html");

            Multipart multipart = new MimeMultipart();
            multipart.addBodyPart(messageBodyPart);

            message.setContent(multipart);

            Transport.send(message);
            logger.info("Mail sent to : " + toEmail);
        } catch (Exception ex) {
            logger.error("Mail fail");
            logger.error("Error : ", ex);

        }

    }
}
