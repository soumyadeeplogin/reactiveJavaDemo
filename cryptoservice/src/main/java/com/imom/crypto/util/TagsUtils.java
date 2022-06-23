package com.imom.crypto.util;

import com.amazonaws.services.kms.model.Tag;
import com.imom.crypto.config.Config;

import java.time.LocalDate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static com.imom.crypto.util.Constants.*;

public class TagsUtils {
    private TagsUtils() {}

    public static List<Tag> getKMSTags() {
        List<Tag> tags = new ArrayList<>();
        Tag envTag = new Tag().withTagKey(ENV).withTagValue(Config.getEnv());
        tags.add(envTag);
        Tag teamTag = new Tag().withTagKey(TEAM).withTagValue(Config.getModule());
        tags.add(teamTag);
        Tag ownerTag = new Tag().withTagKey(OWNER).withTagValue(Config.getOwnerName());
        tags.add(ownerTag);
        Tag ownerEmailTag = new Tag().withTagKey(OWNEREMAIL).withTagValue(Config.getEmailId());
        tags.add(ownerEmailTag);
        Tag RenewaldateTag = new Tag().withTagKey(RENEWALDATE).withTagValue((LocalDate.now().getDayOfMonth())+getMonth()+getYear());
        tags.add(RenewaldateTag);
        Tag creationdateTag = new Tag().withTagKey(CREATIONDATE).withTagValue((LocalDate.now().getDayOfMonth())+getMonth()+(LocalDate.now().getYear()));
        tags.add(creationdateTag);
        Tag reasonTag = new Tag().withTagKey(REASON).withTagValue(Config.getReason());
        tags.add(reasonTag);
        Tag moduleTag = new Tag().withTagKey(MODULE).withTagValue(Config.getModule());
        tags.add(moduleTag);
        return tags;
    }

    public static List<com.amazonaws.services.secretsmanager.model.Tag> getSecreteManagerTags() {
        List<com.amazonaws.services.secretsmanager.model.Tag> tags = new ArrayList<>();
com.amazonaws.services.secretsmanager.model.Tag teamTag = new com.amazonaws.services.secretsmanager.model.Tag();
        teamTag.setKey(TEAM);
        teamTag.setValue(Config.getModule());
        tags.add(teamTag);

        com.amazonaws.services.secretsmanager.model.Tag envTag = new com.amazonaws.services.secretsmanager.model.Tag();
        envTag.setKey(ENV);
        envTag.setValue(Config.getEnv());
        tags.add(envTag);

        com.amazonaws.services.secretsmanager.model.Tag ownerTag = new com.amazonaws.services.secretsmanager.model.Tag();
        ownerTag.setKey(OWNER);
        ownerTag.setValue(Config.getOwnerName());
        tags.add(ownerTag);

        com.amazonaws.services.secretsmanager.model.Tag ownerEmailTag = new com.amazonaws.services.secretsmanager.model.Tag();
        ownerEmailTag.setKey(OWNEREMAIL);
        ownerEmailTag.setValue(Config.getOwnerEmailId());
        tags.add(ownerEmailTag);

        com.amazonaws.services.secretsmanager.model.Tag RenewaldateTag = new com.amazonaws.services.secretsmanager.model.Tag();
        RenewaldateTag.setKey(RENEWALDATE);
        RenewaldateTag.setValue((LocalDate.now().getDayOfMonth())+getMonth()+getYear());
        tags.add(RenewaldateTag);

        com.amazonaws.services.secretsmanager.model.Tag CreationdateTag = new com.amazonaws.services.secretsmanager.model.Tag();
        CreationdateTag.setKey(CREATIONDATE);
        CreationdateTag.setValue((LocalDate.now().getDayOfMonth())+getMonth()+(LocalDate.now().getYear()));
        tags.add(CreationdateTag);

        com.amazonaws.services.secretsmanager.model.Tag reasonTag = new com.amazonaws.services.secretsmanager.model.Tag();
        reasonTag.setKey(REASON);
        reasonTag.setValue(Config.getReason());
        tags.add(reasonTag);

        com.amazonaws.services.secretsmanager.model.Tag modeuleTad = new com.amazonaws.services.secretsmanager.model.Tag();
        modeuleTad.setKey(MODULE);
        modeuleTad.setValue(Config.getModule());
        tags.add(modeuleTad);
        return tags;
    }

    private static String getMonth() {
       return LocalDate.now().getMonth().name().charAt(0) +LocalDate.now().getMonth().name().toLowerCase().substring(1,3);
    }

    private static String getYear() {
        List<String> envs = Arrays.asList("prod","prodir","prodca","prodcr","prod-ca");
        if(envs.contains(Config.getEnv()))
            return String.valueOf(LocalDate.now().getYear()+2);
        else return String.valueOf(LocalDate.now().getYear()+1);
    }
}
