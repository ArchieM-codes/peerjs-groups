/**
 * A robust peer-to-peer group chat library with fine-grained event handling,
 * private messaging, bot integration, and XSS-safe message processing, moderation and peer admin
 * @module PeerGroups
 * 
 */

/**
 * Escape HTML special characters to prevent XSS attacks.
 * @param {string} str
 * @returns {string}
 */
function escapeHTML(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/**
 * Known event types for PeerGroups components.
 * @readonly
 * @enum {string}
 */
const PeerGroupEvents = Object.freeze({
  OPEN: 'open',
  ERROR: 'error',
  CONNECT: 'connect',
  DISCONNECT: 'disconnect',
  JOIN_REQUEST: 'joinRequest',
  JOIN_APPROVED: 'joinApproved',
  JOIN_REJECTED: 'joinRejected',
  MEMBER_JOINED: 'memberJoined',
  MEMBER_LEFT: 'memberLeft',
  MEMBER_LIST: 'memberList',
  MESSAGE: 'message',
  PRIVATE_MESSAGE: 'privateMessage',
  NICKNAME_CHANGED: 'nicknameChanged',
  KICKED: 'kicked',
  BANNED: 'banned',
  UNBANNED: 'unbanned',
  SHUTDOWN: 'shutdown',
  MESSAGE_CENSORED: 'messageCensored'
});

/**
 * Priority-based event listener.
 * @class
 */
class EventListener {
  /**
   * @param {string} eventType
   * @param {Function} callback
   * @param {number} [priority=0]
   */
  constructor(eventType, callback, priority = 0) {
    this.eventType = eventType;
    this.callback = callback;
    this.priority = priority;
    this.active = true;
  }
}

/**
 * Enhanced emitter using EventListener instances.
 * @class
 */
class AdvancedEmitter {
  constructor() {
    /** @type {Map<string, EventListener[]>} */
    this._listeners = new Map();
  }

  /**
   * Add a listener.
   * @param {EventListener} listener
   * @returns {this}
   */
  addListener(listener) {
    if (!listener.active) return this;
    const arr = this._listeners.get(listener.eventType) || [];
    arr.push(listener);
    arr.sort((a, b) => b.priority - a.priority);
    this._listeners.set(listener.eventType, arr);
    return this;
  }

  /**
   * Remove a listener or all listeners for an event.
   * @param {string} eventType
   * @param {Function} [callback]
   * @returns {this}
   */
  removeListener(eventType, callback) {
    if (!this._listeners.has(eventType)) return this;
    if (!callback) {
      this._listeners.delete(eventType);
    } else {
      const filtered = this._listeners
        .get(eventType)
        .filter(l => l.callback !== callback);
      this._listeners.set(eventType, filtered);
    }
    return this;
  }

  /**
   * Emit an event.
   * @param {string} eventType
   * @param  {...any} args
   */
  emit(eventType, ...args) {
    const listeners = this._listeners.get(eventType) || [];
    for (const listener of listeners) {
      if (listener.active) {
        try {
          listener.callback(...args);
        } catch (err) {
          console.error(`Error in listener for ${eventType}:`, err);
        }
      }
    }
  }
}

/**
 * Base class for Host, Client, Bot and PeerAdmin
 * @extends AdvancedEmitter
 */
class PeerGroupsBase extends AdvancedEmitter {
  constructor() {
    super();
  }
}

/**
 * @class Host
 * @extends PeerGroupsBase
 * @fires PeerGroupEvents.*
 */
class Host extends PeerGroupsBase {
  /**
   * @param {string} groupId
   * @param {object} [options]
   * @param {object} [moderationOptions] Options to configure moderation
   * @param {Array<string>} [moderationOptions.bannedWords] List of words to censor
   */
  constructor(groupId, options = {}, moderationOptions = {}) {
    super();
    this.groupId = groupId;
    this.peer = new Peer(groupId, options);
    /** @type {Map<string, {conn: Peer.DataConnection, nickname: string}>} */
    this._members = new Map();
    /** @type {Set<string>} */
    this._banned = new Set();

    //Moderation Feature
    this.moderationOptions = moderationOptions;
    this.bannedWords = new Set(moderationOptions.bannedWords || []);

    this.peer.on('open', id => this.emit(PeerGroupEvents.OPEN, id));
    this.peer.on('error', err => this.emit(PeerGroupEvents.ERROR, err));
    this.peer.on('connection', conn => this._onConnection(conn));
  }

  _onConnection(conn) {
    const clientId = conn.peer;
    conn.on('open', () => {
      this.emit(PeerGroupEvents.CONNECT, clientId);
      conn.on('data', data => this._onData(conn, data));
      conn.on('close', () => this._onPeerClose(clientId));
    });
  }

  _onData(conn, raw) {
    const clientId = conn.peer;
    const data = raw && raw.type ? raw : {};
    switch (data.type) {
      case 'joinRequest':
        if (this._banned.has(clientId)) {
          this._send(conn, { type: 'joinRejected', reason: 'banned' });
          this.emit(PeerGroupEvents.BANNED, clientId);
          return;
        }
        this.emit(
          PeerGroupEvents.JOIN_REQUEST,
          clientId,
          data.nickname,
          () => this._approve(conn, data.nickname),
          reason => this._reject(conn, reason)
        );
        break;

      case 'message':
        {
          let msg = escapeHTML(data.payload);
          if (this.bannedWords.size > 0) {
            const originalMessage = msg;
            msg = this._censorMessage(msg);
            if (msg !== originalMessage) {
              this.emit(PeerGroupEvents.MESSAGE_CENSORED, originalMessage, msg, clientId);
            }
          }
          this.emit(PeerGroupEvents.MESSAGE, msg, clientId, this._members.get(clientId)?.nickname);
          this._broadcast({ type: 'message', payload: msg }, clientId);
        }
        break;

      case 'privateMessage':
        {
          let msg = escapeHTML(data.payload);
          if (this.bannedWords.size > 0) {
            const originalMessage = msg;
            msg = this._censorMessage(msg);
            if (msg !== originalMessage) {
              this.emit(PeerGroupEvents.MESSAGE_CENSORED, originalMessage, msg, clientId);
            }
          }
          const to = data.to;
          this.emit(PeerGroupEvents.PRIVATE_MESSAGE, msg, clientId, to);
          this._sendTo(to, { type: 'privateMessage', payload: msg, from: clientId });
        }
        break;

      case 'nicknameChange':
        {
          const oldNick = this._members.get(clientId)?.nickname;
          const newNick = escapeHTML(data.newNickname);
          this._members.get(clientId).nickname = newNick;
          this.emit(PeerGroupEvents.NICKNAME_CHANGED, clientId, oldNick, newNick);
          this._broadcast({ type: 'nicknameChange', newNickname: newNick });
        }
        break;

      default:
        this.emit(PeerGroupEvents.ERROR, new Error(`Unknown data type: ${data.type}`));
    }
  }

  _approve(conn, nickname) {
    const clientId = conn.peer;
    const safeNick = escapeHTML(nickname);
    this._members.set(clientId, { conn, nickname: safeNick });
    this._send(conn, { type: 'joinApproved', nickname: safeNick });
    this.emit(PeerGroupEvents.JOIN_APPROVED, clientId, safeNick);
    this.emit(PeerGroupEvents.MEMBER_JOINED, clientId, safeNick);
    this._updateMemberList();
  }

  _reject(conn, reason) {
    this._send(conn, { type: 'joinRejected', reason });
    conn.close();
    this.emit(PeerGroupEvents.JOIN_REJECTED, conn.peer, reason);
  }

  _onPeerClose(clientId) {
    const info = this._members.get(clientId);
    if (info) {
      this._members.delete(clientId);
      this.emit(PeerGroupEvents.DISCONNECT, clientId);
      this.emit(PeerGroupEvents.MEMBER_LEFT, clientId, info.nickname);
      this._updateMemberList();
    }
  }

  _broadcast(message, excludeId) {
    for (const [id, { conn }] of this._members) {
      if (id !== excludeId) {
        this._send(conn, message);
      }
    }
  }

  _sendTo(targetId, message) {
    const entry = this._members.get(targetId);
    if (entry) {
      this._send(entry.conn, message);
    }
  }

  _send(conn, message) {
    try {
      conn.send(message);
    } catch (err) {
      this.emit(PeerGroupEvents.ERROR, err);
    }
  }

  _updateMemberList() {
    const list = Array.from(this._members.entries())
      .map(([id, { nickname }]) => ({ id, nickname }));
    this.emit(PeerGroupEvents.MEMBER_LIST, list);
    this._broadcast({ type: 'memberList', list });
  }

  /**
   * Send a broadcast message as host.
   * @param {string} text
   */
  send(text) {
    let msg = escapeHTML(text);
    if (this.bannedWords.size > 0) {
      const originalMessage = msg;
      msg = this._censorMessage(msg);
      if (msg !== originalMessage) {
        this.emit(PeerGroupEvents.MESSAGE_CENSORED, originalMessage, msg, this.peer.id);
      }
    }
    this._broadcast({ type: 'message', payload: msg });
    this.emit(PeerGroupEvents.MESSAGE, msg, this.peer.id, '(host)');
  }

  /**
   * Send a private message to a specific member.
   * @param {string} targetId
   * @param {string} text
   */
  sendPrivate(targetId, text) {
    let msg = escapeHTML(text);
    if (this.bannedWords.size > 0) {
      const originalMessage = msg;
      msg = this._censorMessage(msg);
      if (msg !== originalMessage) {
        this.emit(PeerGroupEvents.MESSAGE_CENSORED, originalMessage, msg, this.peer.id);
      }
    }
    this._sendTo(targetId, { type: 'privateMessage', payload: msg, from: this.peer.id });
    this.emit(PeerGroupEvents.PRIVATE_MESSAGE, msg, this.peer.id, targetId);
  }

  /**
   * Kick a member out.
   * @param {string} clientId
   * @param {string} [reason]
   */
  kick(clientId, reason = 'kicked') {
    const entry = this._members.get(clientId);
    if (entry) {
      this._send(entry.conn, { type: 'kicked', reason });
      entry.conn.close();
      this.emit(PeerGroupEvents.KICKED, clientId, reason);
    }
  }

  /**
   * Ban a member.
   * @param {string} clientId
   */
  ban(clientId) {
    this._banned.add(clientId);
    this.kick(clientId, 'banned');
    this.emit(PeerGroupEvents.BANNED, clientId);
  }

  /**
   * Unban a member.
   * @param {string} clientId
   */
  unban(clientId) {
    this._banned.delete(clientId);
    this.emit(PeerGroupEvents.UNBANNED, clientId);
  }

  /**
   * Add a banned word.
   * @param {string} word
   */
  addBannedWord(word) {
    this.bannedWords.add(word);
  }

  /**
   * Remove a banned word.
   * @param {string} word
   */
  removeBannedWord(word) {
    this.bannedWords.delete(word);
  }

  /**
   * Censor a message if it contains banned words.
   * @param {string} message
   * @returns {string}
   */
  _censorMessage(message) {
    let censoredMessage = message;
    for (const word of this.bannedWords) {
      const regex = new RegExp(`\\b${word}\\b`, 'gi');
      censoredMessage = censoredMessage.replace(regex, '****');
    }
    return censoredMessage;
  }

  /**
   * Shut down the host and disconnect all.
   */
  close() {
    for (const { conn } of this._members.values()) {
      conn.close();
    }
    this.peer.destroy();
    this.emit(PeerGroupEvents.SHUTDOWN);
  }
}

/**
 * @class Client
 * @extends PeerGroupsBase
 * @fires PeerGroupEvents.*
 */
class Client extends PeerGroupsBase {
  /**
   * @param {string} clientId
   * @param {string} groupId
   * @param {object} [options]
   */
  constructor(clientId, groupId, options = {}) {
    super();
    this.clientId = clientId;
    this.groupId = groupId;
    this.peer = new Peer(clientId, options);
    this.conn = null;
    this.nickname = null;

    this.peer.on('open', id => this.emit(PeerGroupEvents.OPEN, id));
    this.peer.on('error', err => this.emit(PeerGroupEvents.ERROR, err));
  }

  /**
   * Request to join a host.
   * @param {string} hostId
   * @param {string} nickname
   */
  join(hostId, nickname) {
    this.nickname = escapeHTML(nickname);
    this.conn = this.peer.connect(hostId);
    this.conn.on('open', () => {
      this.emit(PeerGroupEvents.CONNECT, hostId);
      this._send({ type: 'joinRequest', nickname: this.nickname });
    });
    this.conn.on('data', data => this._onData(data));
    this.conn.on('close', () => this.emit(PeerGroupEvents.DISCONNECT, hostId));
  }

  _onData(raw) {
    const data = raw && raw.type ? raw : {};
    switch (data.type) {
      case 'joinApproved':
        this.emit(PeerGroupEvents.JOIN_APPROVED, this.peer.id, data.nickname);
        break;
      case 'joinRejected':
        this.emit(PeerGroupEvents.JOIN_REJECTED, data.reason);
        break;
      case 'message':
        this.emit(PeerGroupEvents.MESSAGE, data.payload, data.from || this.conn.peer);
        break;
      case 'privateMessage':
        this.emit(
          PeerGroupEvents.PRIVATE_MESSAGE,
          data.payload,
          data.from || this.conn.peer
        );
        break;
      case 'memberList':
        this.emit(PeerGroupEvents.MEMBER_LIST, data.list);
        break;
      case 'kicked':
        this.emit(PeerGroupEvents.KICKED, data.reason);
        this.conn.close();
        break;
      case 'shutdown':
        this.emit(PeerGroupEvents.SHUTDOWN);
        this.conn.close();
        break;
      default:
        this.emit(PeerGroupEvents.ERROR, new Error(`Unknown data: ${data.type}`));
    }
  }

  /**
   * Send a group message.
   * @param {string} text
   */
  send(text) {
    const msg = escapeHTML(text);
    this._send({ type: 'message', payload: msg });
  }

  /**
   * Send a private message to another peer.
   * @param {string} targetId
   * @param {string} text
   */
  sendPrivate(targetId, text) {
    const msg = escapeHTML(text);
    this._send({ type: 'privateMessage', payload: msg, to: targetId });
  }

  /**
   * Change your nickname.
   * @param {string} newNick
   */
  changeNickname(newNick) {
    const nick = escapeHTML(newNick);
    this.nickname = nick;
    this._send({ type: 'nicknameChange', newNickname: nick });
  }

  /**
   * Disconnect from host.
   */
  disconnect() {
    if (this.conn) {
      this.conn.close();
    }
  }

  _send(data) {
    try {
      this.conn.send(data);
    } catch (err) {
      this.emit(PeerGroupEvents.ERROR, err);
    }
  }
}

/**
 * @class Bot
 * @extends Client
 * A bot that processes slash commands and auto-responds or emits.
 */
class Bot extends Client {
  constructor(clientId, groupId, options = {}) {
    super(clientId, groupId, options);
    /** @type {Map<string, Function>} */
    this._commands = new Map();
    this.on(PeerGroupEvents.MESSAGE, (msg, from) => this._handleMessage(msg, from));
  }

  /**
   * Register a slash command.
   * @param {string} commandName without slash, e.g. "help"
   * @param {Function} handler (args: string[], fromId: string) => void
   */
  registerCommand(commandName, handler) {
    this._commands.set(commandName, handler);
  }

  _handleMessage(rawMsg, from) {
    if (!rawMsg.startsWith('/')) return;
    const parts = rawMsg.slice(1).split(/\s+/);
    const cmd = parts.shift();
    const handler = this._commands.get(cmd);
    if (handler) {
      try {
        handler(parts, from);
      } catch (err) {
        this.emit(PeerGroupEvents.ERROR, err);
      }
    }
  }
}

/**
 * @class PeerAdmin
 * @extends PeerGroupsBase
 * Allows administrative control over peers within a group.  Must authenticate.
 */
class PeerAdmin extends PeerGroupsBase {
  /**
   * @param {string} adminId
   * @param {string} groupId
   * @param {string} secret Admin secret to authenticate
   * @param {object} [options]
   */
  constructor(adminId, groupId, secret, options = {}) {
    super();
    this.adminId = adminId;
    this.groupId = groupId;
    this.secret = secret;
    this.peer = new Peer(adminId, options);
    this.conn = null;
    this.authenticated = false;

    this.peer.on('open', id => this.emit(PeerGroupEvents.OPEN, id));
    this.peer.on('error', err => this.emit(PeerGroupEvents.ERROR, err));
  }

  /**
   * Connects to the host and attempts to authenticate as an administrator.
   * @param {string} hostId The Peer ID of the host to connect to.
   */
  connect(hostId) {
    this.conn = this.peer.connect(hostId);
    this.conn.on('open', () => {
      this.emit(PeerGroupEvents.CONNECT, hostId);
      this._send({ type: 'adminAuth', secret: this.secret });
    });
    this.conn.on('data', data => this._onData(data));
    this.conn.on('close', () => {
      this.authenticated = false;
            this.emit(PeerGroupEvents.DISCONNECT, hostId);
    });
  }

  _onData(raw) {
    const data = raw && raw.type ? raw : {};

    switch (data.type) {
      case 'adminAuthSuccess':
        this.authenticated = true;
        this.emit('adminAuthSuccess');
        break;

      case 'adminAuthFailed':
        this.authenticated = false;
        this.emit('adminAuthFailed', data.reason);
        this.conn.close();
        break;

      case 'memberList':
        this.emit(PeerGroupEvents.MEMBER_LIST, data.list);
        break;

      default:
        this.emit(PeerGroupEvents.ERROR, new Error(`Unknown data type: ${data.type}`));
    }
  }

  /**
   * Kicks a user from the peer group.  Requires admin authentication.
   * @param {string} targetClientId The Peer ID of the client to kick.
   * @param {string} reason The reason for the kick.
   */
  kickClient(targetClientId, reason) {
    if (!this.authenticated) {
      this.emit(PeerGroupEvents.ERROR, new Error('Admin not authenticated'));
      return;
    }
    this._send({ type: 'adminKickClient', targetClientId, reason });
  }

  /**
   * Bans a user from the peer group. Requires admin authentication.
   * @param {string} targetClientId The Peer ID of the client to ban.
   */
  banClient(targetClientId) {
    if (!this.authenticated) {
      this.emit(PeerGroupEvents.ERROR, new Error('Admin not authenticated'));
      return;
    }
    this._send({ type: 'adminBanClient', targetClientId });
  }

  /**
   * Unbans a user from the peer group. Requires admin authentication.
   * @param {string} targetClientId The Peer ID of the client to unban.
   */
  unbanClient(targetClientId) {
    if (!this.authenticated) {
      this.emit(PeerGroupEvents.ERROR, new Error('Admin not authenticated'));
      return;
    }
    this._send({ type: 'adminUnbanClient', targetClientId });
  }

  /**
   * Adds a banned word to the host's moderation list. Requires admin authentication.
   * @param {string} word The word to ban.
   */
  addBannedWord(word) {
    if (!this.authenticated) {
      this.emit(PeerGroupEvents.ERROR, new Error('Admin not authenticated'));
      return;
    }
    this._send({ type: 'adminAddBannedWord', word });
  }

  /**
   * Removes a banned word from the host's moderation list. Requires admin authentication.
   * @param {string} word The word to unban.
   */
  removeBannedWord(word) {
    if (!this.authenticated) {
      this.emit(PeerGroupEvents.ERROR, new Error('Admin not authenticated'));
      return;
    }
    this._send({ type: 'adminRemoveBannedWord', word });
  }

  /**
   * Shuts down the peer group. Requires admin authentication.
   */
  shutdownGroup() {
    if (!this.authenticated) {
      this.emit(PeerGroupEvents.ERROR, new Error('Admin not authenticated'));
      return;
    }
    this._send({ type: 'adminShutdownGroup' });
  }

  /**
   * Disconnects from the host.
   */
  disconnect() {
    if (this.conn) {
      this.conn.close();
    }
  }

  _send(data) {
    try {
      this.conn.send(data);
    } catch (err) {
      this.emit(PeerGroupEvents.ERROR, err);
    }
  }
}

// ----- Host Modifications -----

// Extending Host class to handle admin requests
Host.prototype._onData = function(conn, raw) {
  const clientId = conn.peer;
  const data = raw && raw.type ? raw : {};
  switch (data.type) {
    // ... (Previous cases remain the same)

    case 'adminAuth':
      if (data.secret === this.adminSecret) {
        this._send(conn, { type: 'adminAuthSuccess' });
        this.emit('adminAuthenticated', clientId);
      } else {
        this._send(conn, { type: 'adminAuthFailed', reason: 'Invalid secret' });
        conn.close();
        this.emit('adminAuthenticationFailed', clientId);
      }
      break;

    case 'adminKickClient':
      this.kick(data.targetClientId, data.reason || 'Kicked by admin');
      break;

    case 'adminBanClient':
      this.ban(data.targetClientId);
      break;

    case 'adminUnbanClient':
      this.unban(data.targetClientId);
      break;

    case 'adminAddBannedWord':
      this.addBannedWord(data.word);
      break;

    case 'adminRemoveBannedWord':
      this.removeBannedWord(data.word);
      break;

    case 'adminShutdownGroup':
      this.close();
      break;

    default:
      PeerGroupsBase.prototype._onData.call(this, conn, raw);  // Use the base class handler for other types
      break;
  }
};

/**
 *  Set up the host's admin functionality.
 *  @param {string} secret
 */
Host.prototype.setupAdmin = function(secret){
  this.adminSecret = secret;
  return this;
};

// Export the module for node or browser
// at the end of peergroups.js

// Export for Node.js (using module.exports if available)
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { escapeHTML, PeerGroupEvents, EventListener, AdvancedEmitter, Host, Client, Bot, PeerAdmin };
}

// Expose globally for browsers (if window is defined)
if (typeof window !== 'undefined') {
  window.PeerGroups = { escapeHTML, PeerGroupEvents, EventListener, AdvancedEmitter, Host, Client, Bot, PeerAdmin };
}

