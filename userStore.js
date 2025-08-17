const fs = require('fs').promises;
const path = require('path');

class UserStore {
  constructor(dataFile = 'users.json') {
    this.dataFile = path.join(__dirname, dataFile);
    this.users = [];
    this.loadUsers();
  }

  async loadUsers() {
    try {
      const data = await fs.readFile(this.dataFile, 'utf8');
      this.users = JSON.parse(data);
    } catch (error) {
      // File doesn't exist or is empty, start with empty array
      this.users = [];
      await this.saveUsers();
    }
  }

  async saveUsers() {
    try {
      await fs.writeFile(this.dataFile, JSON.stringify(this.users, null, 2));
    } catch (error) {
      console.error('Error saving users:', error);
      throw error;
    }
  }

  async createUser(userData) {
    // Check if email already exists
    const existingUser = this.users.find(u => u.email === userData.email);
    if (existingUser) {
      throw new Error('User with this email already exists');
    }

    // Check if handle already exists
    const existingHandle = this.users.find(u => u.handle === userData.handle);
    if (existingHandle) {
      // Generate unique handle
      let counter = 1;
      let newHandle = userData.handle;
      while (this.users.find(u => u.handle === newHandle)) {
        newHandle = userData.handle + counter;
        counter++;
      }
      userData.handle = newHandle;
    }

    this.users.push(userData);
    await this.saveUsers();
    return userData;
  }

  async findById(id) {
    return this.users.find(user => user.id === id);
  }

  async findByEmail(email) {
    return this.users.find(user => user.email === email);
  }

  async findByHandle(handle) {
    return this.users.find(user => user.handle === handle);
  }

  async findByGoogleId(googleId) {
    return this.users.find(user => user.googleId === googleId);
  }

  async updateUser(id, updates) {
    const userIndex = this.users.findIndex(user => user.id === id);
    if (userIndex === -1) {
      throw new Error('User not found');
    }

    // Don't allow changing email or id
    delete updates.email;
    delete updates.id;

    this.users[userIndex] = { ...this.users[userIndex], ...updates };
    await this.saveUsers();
    return this.users[userIndex];
  }

  async deleteUser(id) {
    const userIndex = this.users.findIndex(user => user.id === id);
    if (userIndex === -1) {
      throw new Error('User not found');
    }

    this.users.splice(userIndex, 1);
    await this.saveUsers();
    return true;
  }

  async getAllUsers() {
    // Return users without sensitive data
    return this.users.map(user => ({
      id: user.id,
      email: user.email,
      name: user.name,
      handle: user.handle,
      bio: user.bio,
      photo: user.photo,
      createdAt: user.createdAt,
      emailVerified: user.emailVerified
    }));
  }

  async getUserStats() {
    return {
      totalUsers: this.users.length,
      verifiedUsers: this.users.filter(u => u.emailVerified).length,
      googleUsers: this.users.filter(u => u.googleId).length
    };
  }
}

module.exports = UserStore;