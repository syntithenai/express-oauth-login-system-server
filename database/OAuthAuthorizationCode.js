const mongoose = require('mongoose');

const Schema = mongoose.Schema;

const OAuthAuthorizationCodeSchema = new Schema({
  code: String,
  expiresAt: Date,
  redirectUri: String,
  scope: String,
  user: { type: Schema.Types.ObjectId, ref: 'User' },
  client: { type: Schema.Types.ObjectId, ref: 'OAuthClient' }
});
OAuthAuthorizationCodeSchema.virtual('id').get(function () {
  return this._id;
});
module.exports = mongoose.model('OAuthAuthorizationCode', OAuthAuthorizationCodeSchema);
