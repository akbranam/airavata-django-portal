import BaseModel from "./BaseModel";

const FIELDS = [
  "userId",
  "gatewayId",
  "email",
  "firstName",
  "lastName",
  "enabled",
  "emailVerified",
  {
    name: "creationTime",
    type: 'date',
  },
];

export default class UnverifiedEmailUserProfile extends BaseModel {
  constructor(data = {}) {
    super(FIELDS, data);
  }
}
