require('dotenv').config();
const express = require('express');
const axios = require('axios');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const app = express();

app.use(bodyParser.json());

// Handle favicon requests
app.get('/favicon.ico', (req, res) => res.status(204).end());

const APP_ID = process.env.OCULUS_APP_ID;    
const APP_SECRET = process.env.OCULUS_SECRET; 
const JWT_SECRET = process.env.JWT_SECRET;
const PLAYFAB_TITLE_ID = process.env.PLAYFAB_TITLE_ID;
const PLAYFAB_SECRET_KEY = process.env.PLAYFAB_SECRET_KEY;

async function getPlayFabPlayerIdFromOculus(oculusId) {
    try {
        const response = await axios.post(
            `https://${PLAYFAB_TITLE_ID}.playfabapi.com/Server/GetPlayFabIDsFromOculusIDs`,
            {
                OculusIds: [oculusId.toString()]
            },
            {
                headers: {
                    'X-SecretKey': PLAYFAB_SECRET_KEY,
                    'Content-Type': 'application/json'
                }
            }
        );
        
        if (response.data.data && response.data.data.OculusPlayFabIdPairs.length > 0) {
            return response.data.data.OculusPlayFabIdPairs[0].PlayFabId;
        }
        return null;
    } catch (error) {
        console.error("PlayFab lookup error:", error.response?.data || error.message);
        return null;
    }
}

async function getPlayFabSessionTicket(playFabId) {
    try {
        const response = await axios.post(
            `https://${PLAYFAB_TITLE_ID}.playfabapi.com/Server/AuthenticateSessionTicket`,
            {
                SessionTicket: playFabId 
            },
            {
                headers: {
                    'X-SecretKey': PLAYFAB_SECRET_KEY,
                    'Content-Type': 'application/json'
                }
            }
        );
        
        return response.data.data !== null;
    } catch (error) {
        console.error("PlayFab session error:", error.response?.data || error.message);
        return false;
    }
}

app.post('/api/login', async (req, res) => {
    const { userId, nonce } = req.body;
    
    if (!userId || !nonce) {
        return res.status(400).json({ error: "Missing userId or nonce" });
    }
    
    try {
        const appAccessToken = `OC|${APP_ID}|${APP_SECRET}`;
        const metaResponse = await axios.post('https://graph.oculus.com/user_nonce_validate', null, {
            params: {
                access_token: appAccessToken,
                nonce: nonce,
                user_id: userId
            }
        });
        
        if (metaResponse.data.is_valid !== true) {
            console.log(`Failed verification for ${userId}`);
            return res.status(401).json({ error: "Invalid Oculus Entitlement" });
        }
        
        const playFabId = await getPlayFabPlayerIdFromOculus(userId);
        
        if (!playFabId) {
            console.log(`No PlayFab ID found for Oculus user ${userId}`);
            return res.status(401).json({ error: "PlayFab account not found" });
        }
        
        const token = jwt.sign({ 
            oculusId: userId,
            playFabId: playFabId,
            scope: "player" 
        }, JWT_SECRET, { expiresIn: '6h' });
        
        console.log(`Verified Oculus User ${userId} (PlayFab: ${playFabId}). Issued Token.`);
        return res.json({ 
            token: token,
            playFabId: playFabId
        }); 
    } catch (error) {
        console.error("Meta API Error:", error.response?.data || error.message);
        return res.status(500).json({ error: "Verification Failed" });
    }
});

app.post('/api/photon-auth', (req, res) => {
    const clientToken = req.body.token || req.query.token;
    
    if (!clientToken) {
        return res.json({ 
            ResultCode: 2, 
            Message: "Missing Session Token" 
        });
    }
    
    try {
        const decoded = jwt.verify(clientToken, JWT_SECRET);
        
        if (!decoded.oculusId || !decoded.playFabId) {
            return res.json({ 
                ResultCode: 1, 
                Message: "Invalid token data" 
            });
        }
        
        console.log(`Photon auth success for PlayFab: ${decoded.playFabId}`);
        
        return res.json({ 
            ResultCode: 0,
            Message: "Success",
            UserId: decoded.playFabId 
        });
    } catch (err) {
        console.error("Token verification failed:", err.message);
        
        return res.json({ 
            ResultCode: 1, 
            Message: "Invalid or Expired Token" 
        });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Backend running on port ${PORT}`));
