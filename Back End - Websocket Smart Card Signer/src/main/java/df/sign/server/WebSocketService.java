package df.sign.server;

import java.io.StringReader;
import java.util.ArrayList;
import java.util.List;

import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonArrayBuilder;
import javax.json.JsonObject;
import javax.json.JsonValue.ValueType;
import javax.websocket.OnClose;
import javax.websocket.OnError;
import javax.websocket.OnMessage;
import javax.websocket.OnOpen;
import javax.websocket.Session;
import javax.websocket.server.ServerEndpoint;

import df.sign.SignFactory;
import df.sign.SignUI;
import df.sign.SignUtils;
import df.sign.datastructure.Data;
import df.sign.datastructure.SignConfig;

@ServerEndpoint(value = "/sign")
public class WebSocketService {
    private Session session = null;

    public void sendTestData() {
        session.getAsyncRemote().sendText("{\"dataSigned\" : []}");
    }

    @OnOpen
    public void open(Session session) {
        this.session = session;
    }

    @OnClose
    public void onClose(Session session) {}

    @OnError
    public void onError(Throwable exception, Session session) {}

    @OnMessage
    public String startSignProcess(String message, Session session) {
        try {
            // Assuming message is a raw JSON array like: [{...}, {...}]
            JsonObject jsonObject = Json.createReader(new StringReader(message)).readObject();
            JsonArray dataToSignArray = jsonObject.getJsonArray("dataToSign");


            List<Data> dataToSignList = new ArrayList<>();

            for (int i = 0; i < dataToSignArray.size(); i++) {
                if (dataToSignArray.get(i).getValueType() != ValueType.OBJECT)
                    throw new Exception("Expected Json Object");

                JsonObject obj = dataToSignArray.getJsonObject(i);
                String id = obj.getString("id");
                String contentB64 = obj.getString("contentB64");
                byte[] content = SignUtils.base64Decode(contentB64.getBytes("UTF-8"));

                SignConfig config = new SignConfig();
                JsonObject parameters = obj.getJsonObject("params");

                if (parameters != null) {
                    config.signPdfAsP7m = parameters.getBoolean("signPdfAsP7m", false);
                    config.visibleSignature = parameters.getBoolean("visibleSignature", true);
                    config.pageNumToSign = parameters.getInt("pageNumToSign", -1);
                    config.signPosition = parameters.getString("signPosition", "left");
                }

                dataToSignList.add(new Data(id, content, config));
            }

            List<Data> dataSignedList = SignFactory.performSign(dataToSignList, null); // no dllList

            JsonArrayBuilder jsonArrayBuilder = Json.createArrayBuilder();
            for (Data dataSigned : dataSignedList) {
                String contentB64 = new String(SignUtils.base64Encode(dataSigned.data), "UTF-8");
                jsonArrayBuilder.add(Json.createObjectBuilder()
                        .add("id", dataSigned.id)
                        .add("contentB64", contentB64));
            }

            JsonObject ret = Json.createObjectBuilder().add("dataSigned", jsonArrayBuilder).build();
            return ret.toString();

        } catch (Exception ex) {
            ex.printStackTrace();
            SignUI.showErrorMessage(ex.getMessage());
            return "{\"error\" : \"" + ex.getMessage().replace("\"", "\\\"").replace("\\", "\\\\") + "\"}";
        }
    }
}
