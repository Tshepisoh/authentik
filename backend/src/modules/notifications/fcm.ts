import type { Messaging } from 'firebase-admin/messaging';
import type { PushSender } from './service.js';

export class FcmPushSender implements PushSender {
  constructor(private readonly messaging: Messaging) {}

  async send(tokens: string[], message: { title: string; body: string; alertId: string }) {
    const res = await this.messaging.sendEachForMulticast({
      tokens,
      notification: { title: message.title, body: message.body },
      data: { alertId: message.alertId },
      android: { priority: 'high', notification: { visibility: 'private', channelId: 'security-alerts' } },
      apns: { payload: { aps: { sound: 'default', 'interruption-level': 'time-sensitive' } } },
    });
    const invalidTokens = res.responses
      .map((r, i) => ({ r, token: tokens[i]! }))
      .filter(({ r }) =>
        ['messaging/registration-token-not-registered', 'messaging/invalid-registration-token'].includes(r.error?.code ?? ''),
      )
      .map(({ token }) => token);
    return { invalidTokens };
  }
}
