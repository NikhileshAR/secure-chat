# End-to-End Demo Flow

1. **Admin runs setup**
   - `npm install`
   - `node deploy/setup.js`
   - Set `publicUrl` if users are remote.

2. **Admin shares client bundle**
   - Generate and distribute `client-config.json` and instructions.
   - Users import `client-config.json` in the app Connection screen.

3. **User A opens app and connects**
   - `npm run start:app`
   - Open `http://127.0.0.1:8787`
   - Import config or enter relay URL, click **Connect**.

4. **User B opens app and connects**
   - Same steps as User A.

5. **A scans B QR**
   - B clicks **Share Identity**.
   - A scans QR image or pastes B identity JSON into **Contacts**.
   - A clicks **Add Contact**.

6. **B scans A QR**
   - A clicks **Share Identity**.
   - B scans/pastes and adds A as contact.

7. **A sends message**
   - A selects B in chat.
   - A sends a text message.

8. **B receives message**
   - Poll loop pulls messages every randomized interval.
   - Message appears in B chat with timestamp and `received` status.
