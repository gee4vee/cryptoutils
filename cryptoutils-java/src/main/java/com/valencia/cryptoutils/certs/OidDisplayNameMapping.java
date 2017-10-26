/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2017 Kai Kramer
 *
 * This file is part of KeyStore Explorer.
 *
 * KeyStore Explorer is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * KeyStore Explorer is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with KeyStore Explorer.  If not, see <http://www.gnu.org/licenses/>.
 */
package com.valencia.cryptoutils.certs;

import java.util.HashMap;
import java.util.Map;
import java.util.ResourceBundle;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.style.BCStyle;

/**
 * This class holds the mapping between the OIDs and the display names of RDN components.
 *
 */
public class OidDisplayNameMapping {

    private static ResourceBundle res = ResourceBundle.getBundle("com/valencia/cryptoutils/certs/resources");

    private static final String DC = res.getString("DistinguishedName.jlDomainComponent.text");
    private static final String SURNAME = res.getString("DistinguishedName.jlSurname.text");
    private static final String GIVENNAME = res.getString("DistinguishedName.jlGivenName.text");
    private static final String SN = res.getString("DistinguishedName.jlSerialNumber.text");
    private static final String E = res.getString("DistinguishedName.jlEmailAddress.text");
    private static final String C = res.getString("DistinguishedName.jlCountryCode.text");
    private static final String ST = res.getString("DistinguishedName.jlStateName.text");
    private static final String L = res.getString("DistinguishedName.jlLocalityName.text");
    private static final String O = res.getString("DistinguishedName.jlOrganisationName.text");
    private static final String OU = res.getString("DistinguishedName.jlOrganisationUnit.text");
    private static final String CN = res.getString("DistinguishedName.jlCommonName.text");

    public static final String CN_TOOLTIP = res.getString("DistinguishedName.jtfCommonName.edit.tooltip");
    public static final String OU_TOOLTIP = res.getString("DistinguishedName.jtfOrganisationUnit.edit.tooltip");
    public static final String O_TOOLTIP = res.getString("DistinguishedName.jtfOrganisationName.edit.tooltip");
    public static final String L_TOOLTIP = res.getString("DistinguishedName.jtfLocalityName.edit.tooltip");
    public static final String ST_TOOLTIP = res.getString("DistinguishedName.jtfStateName.edit.tooltip");
    public static final String C_TOOLTIP = res.getString("DistinguishedName.jtfCountryCode.edit.tooltip");
    public static final String E_TOOLTIP = res.getString("DistinguishedName.jtfEmailAddress.edit.tooltip");

    private static Map<String, ASN1ObjectIdentifier> displayNameToOID = new HashMap<String, ASN1ObjectIdentifier>();
    static {
        displayNameToOID.put(CN, BCStyle.CN);
        displayNameToOID.put(OU, BCStyle.OU);
        displayNameToOID.put(O, BCStyle.O);
        displayNameToOID.put(L, BCStyle.L);
        displayNameToOID.put(ST, BCStyle.ST);
        displayNameToOID.put(C, BCStyle.C);
        displayNameToOID.put(E, BCStyle.E);

        displayNameToOID.put(SN, BCStyle.SN);
        displayNameToOID.put(GIVENNAME, BCStyle.GIVENNAME);
        displayNameToOID.put(SURNAME, BCStyle.SURNAME);
        displayNameToOID.put(DC, BCStyle.DC);
    }

    private static Map<String, String> oidToDisplayName = new HashMap<String, String>();
    static {
        oidToDisplayName.put(BCStyle.CN.getId(), CN);
        oidToDisplayName.put(BCStyle.OU.getId(), OU);
        oidToDisplayName.put(BCStyle.O.getId(), O);
        oidToDisplayName.put(BCStyle.L.getId(), L);
        oidToDisplayName.put(BCStyle.ST.getId(), ST);
        oidToDisplayName.put(BCStyle.C.getId(), C);
        oidToDisplayName.put(BCStyle.E.getId(), E);

        oidToDisplayName.put(BCStyle.SN.getId(), SN);
        oidToDisplayName.put(BCStyle.GIVENNAME.getId(), GIVENNAME);
        oidToDisplayName.put(BCStyle.SURNAME.getId(), SURNAME);
        oidToDisplayName.put(BCStyle.DC.getId(), DC);
    }

    public static String[] getDisplayNames() {
        return new String[] { CN, OU, O, L, ST, C, E, SN, GIVENNAME, SURNAME, DC };
    }

    public static ASN1ObjectIdentifier getOidForDisplayName(String displayName) {
        return displayNameToOID.get(displayName);
    }

    public static String getDisplayNameForOid(String oid) {
        String displayName = oidToDisplayName.get(oid);
        if (displayName == null) {
            // simply use OID as display name for unknown OIDs
            displayName = oid;
        }
        return displayName;
    }
}
