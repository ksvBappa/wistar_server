const { DataTypes } = require('sequelize');
const sequelize = require('../../lib/db');

const User = sequelize.define('User', {
  user_id: {
    type: DataTypes.INTEGER,
    primaryKey: true,
    autoIncrement: true,
    allowNull: false
  },
  username: {
    type: DataTypes.STRING(255),
    allowNull: false,
    validate: {
      notEmpty: { msg: 'Username is required' },
      len: {
        args: [1, 255],
        msg: 'Username must be between 1 and 255 characters'
      }
    }
  },
  user_email: {
    type: DataTypes.STRING(255),
    allowNull: false,
    unique: {
      name: 'user_email',
      msg: 'Email already exists'
    },
    validate: {
      notEmpty: { msg: 'Email is required' },
      isEmail: { msg: 'Invalid email format' }
    }
  },
  user_password: {
    type: DataTypes.STRING(255),
    allowNull: false,
    validate: {
      notEmpty: { msg: 'Password is required' },
      len: {
        args: [6, 255],
        msg: 'Password must be at least 6 characters long'
      }
    }
  },
  user_image: {
    type: DataTypes.STRING(255),
    allowNull: true
  },
  user_ip: {
    type: DataTypes.STRING(45),
    allowNull: true
  },
  user_address: {
    type: DataTypes.TEXT,
    allowNull: true
  },
  user_mobile: {
    type: DataTypes.STRING(20),
    allowNull: true,
    validate: {
      is: {
        args: /^[0-9+\-\s]{0,20}$/,
        msg: 'Invalid mobile number format'
      }
    }
  },
  token: {
    type: DataTypes.STRING(255),
    allowNull: true
  },
  token_created: {
    type: DataTypes.DATE,
    allowNull: true
  },
  created_at: {
    type: DataTypes.DATE,
    allowNull: false,
    defaultValue: DataTypes.NOW
  }
}, {
  tableName: 'user_table',
  timestamps: false // Disable Sequelize's default timestamps (we're using created_at explicitly)
});

// Optional: Add a method to hash passwords before saving
User.beforeCreate(async (user) => {
  if (user.user_password) {
    const bcrypt = require('bcrypt');
    user.user_password = await bcrypt.hash(user.user_password, 10);
  }
});

// Optional: Add a method to compare passwords
User.prototype.comparePassword = async function (password) {
  const bcrypt = require('bcrypt');
  return await bcrypt.compare(password, this.user_password);
};

module.exports = User;
