const mongoose = require('mongoose');

const Schema = mongoose.Schema;

const OAuthRefreshTokenSchema = new Schema({
  refreshToken: String,
  refreshTokenExpiresAt: Schema.Types.Date,
  scope: String,
  user: { type: Schema.Types.ObjectId, ref: 'User' },
  client: { type: Schema.Types.ObjectId, ref: 'OAuthClient' },
});
OAuthRefreshTokenSchema.virtual('id').get(function () {
  return this._id;
});
module.exports = mongoose.model('OAuthRefreshToken', OAuthRefreshTokenSchema);
