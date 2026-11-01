const arl = db.getSiblingDB("arl");

arl.createUser({
  user: process.env.ARL_MONGO_USER,
  pwd: process.env.ARL_MONGO_PASSWORD,
  roles: [{ role: "readWrite", db: "arl" }],
});

arl.user.insertOne({
  username: process.env.ARL_ADMIN_USER,
  password: process.env.ARL_ADMIN_PASSWORD_HASH,
});
