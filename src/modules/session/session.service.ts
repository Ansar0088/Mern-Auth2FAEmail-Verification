import sessionModal from "../../database/models/session.model";

export class SessionService {
  public async getAllSessions(userId: string) {
    const sessions = await sessionModal.find(
      {
        userId,
        expiredAt: { $gt: new Date() },
      },
      {
        _id: 1,
        userAgent: 1,
        expiredAt: 1,
        createdAt: 1,
        userId,
      },{
        sort:{
            createdAt:-1
        },
      }
    );
    return sessions;
  }
}
