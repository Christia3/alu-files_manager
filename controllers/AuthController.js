const sha1 = require('sha1');
const { v4: uuid4 } = require('uuid');
const redisClient = require('../utils/redis');
const dbClient = require('../utils/db');

class AuthController {
  static async getConnect(req, res) {
    try {
      const authHeader = req.headers.authorization;
      
      if (!authHeader || !authHeader.startsWith('Basic ')) {
        return res.status(401).json({ error: 'Unauthorized' });
      }

      const base64Credentials = authHeader.split(' ')[1];
      let credentials;
      
      try {
        credentials = Buffer.from(base64Credentials, 'base64').toString('utf-8');
      } catch (err) {
        return res.status(401).json({ error: 'Unauthorized' });
      }

      const [email, password] = credentials.split(':');
      
      if (!email || !password) {
        return res.status(401).json({ error: 'Unauthorized' });
      }

      const user = await dbClient.db.collection('users').findOne({ 
        email, 
        password: sha1(password) 
      });

      if (!user) {
        return res.status(401).json({ error: 'Unauthorized' });
      }

      const token = uuid4();
      await redisClient.set(`auth_${token}`, user._id.toString(), 86400);

      return res.status(200).json({ token });
    } catch (error) {
      return res.status(500).json({ error: 'Internal Server Error' });
    }
  }

  static async getDisconnect(req, res) {
    const token = req.header('X-Token');
    if (!token) return res.status(401).json({ error: 'Unauthorized' });

    const userId = await redisClient.get(`auth_${token}`);
    if (!userId) return res.status(401).json({ error: 'Unauthorized' });

    await redisClient.del(`auth_${token}`);
    return res.status(204).send();
  }
}

module.exports = AuthController;
