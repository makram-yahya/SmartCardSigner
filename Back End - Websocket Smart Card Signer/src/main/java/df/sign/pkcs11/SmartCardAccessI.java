/*
    Websocket Smartcard Signer
    Copyright (C) 2017  Damiano Falcioni (damiano.falcioni@gmail.com)
    
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.
    
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.
    
    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>. 
 */
package df.sign.pkcs11;

import java.util.ArrayList;

public interface SmartCardAccessI {
    public long[] connectToLibrary(String library) throws Exception, Error;
    public long getPinMinLength(long slotID) throws Exception, Error;
    public long getPinMaxLength(long slotID) throws Exception, Error;
    public ArrayList<CertificateData> getCertificateList(long slotID) throws Exception, Error;
    public long login(long slotID, String pin) throws Exception, Error;
    public byte[] signData(long sessionID, byte[] certId, byte[] certLabel, byte[] data) throws Exception, Error;
    public void closeSession(long sessionID);
    public void disconnectLibrary();

}
