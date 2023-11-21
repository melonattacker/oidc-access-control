const mongoose = require('mongoose');

async function connect() {
  await mongoose.connect('mongodb://user:pass@mongo-rp:27017/oidc-access-control');
  console.log("Connected to MongoDB");
}

async function disconnect() {
  await mongoose.connection.close();
  console.log("Disconnected from MongoDB");
}

const UserSchema = new mongoose.Schema({
  _id: {
    type: String,
    required: true,
  },
  username: { type: String, required: true, unique: true },
  sub: { type: String, required: true, unique: true },
});


const CredentialSchema = new mongoose.Schema({
  _id: {
    type: String,
    required: true,
  },
  publicKey: {
    type: String,
    required: true,
  },
  name: {
    type: String,
    required: true,
  },
  transports: [{
    type: String,
  }],
  registered: {
    type: Date,
    required: true,
    default: Date.now,
  },
  last_used: {
    type: Date,
  },
  user_id: {
    type: String,
    required: true,
  },
});

const RequestLogSchema = new mongoose.Schema({
  sourceIp: String,
  userAgent: String,
  sentTime: Number,
  iat: Number,
  uid: String
});

const RandBytesSchema = new mongoose.Schema({
  sub: { 
    type: String, 
    required: true
  },
  randBytes: {
    type: String,
    required: true
  },
});

const NonceSchema = new mongoose.Schema({
  sub: {
    type: String,
    required: true
  },
  nonce: {
    type: String,
    required: true
  }
});

const UserModel = mongoose.model('User', UserSchema);
const CredentialModel = mongoose.model('Credential', CredentialSchema);
const RequestLogModel = mongoose.model('RequestLog', RequestLogSchema);
const RandBytesModel = mongoose.model('RandBytes', RandBytesSchema);
const NonceModel = mongoose.model('Nonce', NonceSchema);

const Users = {
  findById: async (user_id) => {
    const user = await UserModel.findById(user_id);
    return user;
  },

  findByUsername: async (username) => {
    const user = await UserModel.findOne({ username: username });
    return user;
  },

  findBySub: async (sub) => {
    const user = await UserModel.findOne({ sub: sub });
    return user;
  },

  update: async (user) => {
    console.log("user:", user);
    console.log("User ID:", user._id);
    const updatedUser = await UserModel.findByIdAndUpdate(user.id, user, { new: true});
    console.log("updatedUser:", updatedUser);
    return updatedUser;
  },

  create: async (user) => {
    const newUser = new UserModel(user);
    return await newUser.save();
  }
}

const Credentials = {
  findById: async (credential_id) => {
    const credential = await CredentialModel.findById(credential_id);
    return credential;
  },

  findByUserId: async (user_id) => {
    const results = await CredentialModel.find({ user_id: user_id }).sort({ registered: 'desc' });
    return results;
  },

  update: async (credential) => {
    const updatedCredential = await CredentialModel.findByIdAndUpdate(credential.id, credential, { new: true });
    return updatedCredential;
  },

  remove: async (credential_id) => {
    const result = await CredentialModel.findByIdAndDelete(credential_id);
    return result;
  },

  create: async (credential) => {
    const newCredential = new CredentialModel(credential);
    return await newCredential.save();
  }
}

const RequestLogs = {
  create: async (log) => {
    const newLog = new RequestLogModel(log);
    return await newLog.save();
  },

  findByUID: async (uid) => {
    const log = await RequestLogModel.findOne({ uid: uid });
    return log;
  },

  findByIPAndUA: async (sourceIp, userAgent) => {
    const logs = await RequestLogModel.find({ sourceIp: sourceIp, userAgent: userAgent });
    return logs;
  },

  findAll: async () => {
    return await RequestLogModel.find();
  },

  update: async (log) => {
    const updatedLog = await RequestLogModel.findByIdAndUpdate(log.id, log, { new: true });
    return updatedLog;
  },

  remove: async (logId) => {
    const result = await RequestLogModel.findByIdAndDelete(logId);
    return result;
  }
}

const RandBytes = {
  create: async (randBytes) => {
    const newRandBytes = new RandBytesModel(randBytes);
    return await newRandBytes.save();
  },

  findBySub: async (sub) => {
    const result = await RandBytesModel.find({ sub: sub });
    return result;
  },

  removeBySub: async (sub) => {
    const result = await RandBytesModel.deteleMany({ sub: sub });
    return result;
  }
}

const Nonce = {
  create: async (nonce) => {
    const newNonce = new NonceModel(nonce);
    return await newNonce.save();
  },

  findBySub: async (sub) => {
    const result = await NonceModel.find({ sub: sub });
    return result;
  },

  removeBySub: async (sub) => {
    const result = await NonceModel.deteleMany({ sub: sub });
    return result;
  }
}

module.exports = {
  connect,
  disconnect,
  Users,
  Credentials,
  RequestLogs,
  RandBytes,
  Nonce
}