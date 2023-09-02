const express=require("express");
const app=express();
const bodyParser = require('body-parser');
const mysql = require('mysql');
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');
const session = require('express-session');
const { exit } = require("process");
const { v4: uuidv4 } = require('uuid');
const http = require("http");
const { url } = require("inspector");
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcrypt');
const multer = require('multer');
const nocache = require('nocache');
const path = require('path')
const socketIo = require('socket.io');
const crypto = require('crypto');
const secretKey = crypto.randomBytes(64).toString('hex');
console.log(secretKey);
const server = http.createServer(app);
const io = socketIo(server); 
// Handle socket connections
// Initialize Express app and other middleware
// ...

// Create an HTTP server to handle WebSocket connection

// const loginRoutes = require('./routes/loginRoutes');
// const createTicketRoutes = require('./routes/createTicketRoutes');
// const submitroutes = require('./routes/submitroutes');
// const saveroutes = require('./routes/saveroutes');
// const registerroutes = require('./routes/registerroutes');
// const userdashboardroutes=require('./routes/userdashboardroutes');
// const admindashboardroutes=require('./routes/admindashboardroutes');
dotenv.config();
app.use(express.static(path.join(__dirname, 'public')));
// app.use('/login', loginRoutes);
// app.use('/tickets', createTicketRoutes); 
// app.use('/submit',submitroutes);
// app.use('/save',saveroutes);
// app.use('/register',registerroutes);
// app.use('/userdashboard',userdashboardroutes);
// app.use('/admindashboard',admindashboardroutes);
/* mysql connection */
const con = mysql.createConnection({
  host: process.env.DB_CONNECT_HOST,
  user:process.env.DB_CONNECT_USER,
  password:  process.env.DB_CONNECT_PASS,
  database:process.env.DB_CONNECT_DATABASE
});
con.connect(function(err) {
  if (err) throw err;
  console.log("Connected!");
});
// Multer configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'attachments'); // Upload files to the "attachments" folder
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + '-' + file.originalname); // Set unique file name for each upload
  }
});
const upload = multer({ storage: storage });
app.use(bodyParser.urlencoded({ extended: true }));
app.use(
  session({
	secret: 'secret',
	resave: true,
	saveUninitialized: true
}));
app.get('/socket.io/socket.io.js', (req, res) => {
  res.sendFile(__dirname + '/node_modules/socket.io/client-dist/socket.io.js');
});
app.use('/attachments', express.static(path.join(__dirname, 'attachments')));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'static')));
app.use(express.static(path.join(__dirname, "js")));
app.use(session({
  secret: 'secretkey',
  resave: false,
  saveUninitialized: true
}));
// set modules
app.set("view engine", "ejs");
app.set('views', path.join(__dirname, 'views'));
app.use(passport.session());
app.use(bodyParser.json());
app.use(passport.initialize());
app.use('/userdashboard', nocache());
app.use('/admindashboard', nocache());
app.use(express.urlencoded({extended:true}));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
app.engine('html', require('ejs').renderFile);
app.set('view engine', 'ejs');
app.use(express.static("attachments"));
// Handle socket connections
app.post('/sendmessage', isAuthenticated, (req, res) => {
  const { ticketId, message, role } = req.body;

  // Assuming you have the logic to validate and sanitize input data
  const insertChatMessageQuery = 'INSERT INTO chats (message, ticketId, sendBy) VALUES (?, ?, ?)';
  con.query(insertChatMessageQuery, [message, ticketId, role], (err, result) => {
    if (err) {
      console.error('Error inserting chat message:', err);
      return res.status(500).json({ success: false, message: 'An error occurred.' });
    }

    // Emit the message to the Socket.IO room
    io.to(ticketId).emit('message', {
      message,
      role,
      createdAt: new Date().toLocaleString(),
    });

    res.json({ success: true, message: 'Message sent successfully.' });
  });
});
// Socket.IO setup for real-time chat
io.on('connection', (socket) => {
  console.log('A user connected');

  socket.on('join', (data) => {
    const ticketId = data.ticketId;
    socket.join(ticketId); // Join the room associated with the ticketId

    // Fetch messages for the specific ticketId from the database
    const fetchMessagesQuery = 'SELECT * FROM chats WHERE ticketId = ?';
    con.query(fetchMessagesQuery, [ticketId], (err, rows) => {
      if (err) {
        console.error('Error fetching messages:', err);
      } else {
        const messages = rows.map(row => ({
          message: row.message,
          role: row.sendBy,
          createdAt: new Date(row.createdAt).toLocaleString()
        })); // Extract messages from all rows

        // Emit fetched messages to the client
        io.to(ticketId).emit('initMessages', { messages: messages });
      }
    });
  });

  // More socket event handlers...
  // ...

  socket.on('disconnect', () => {
    console.log('A user disconnected');
  });
});
passport.use('local-user', new LocalStrategy(
  function(username, password, done) {
    // Fetch user from the database based on the username
    const sql = 'SELECT * FROM users WHERE username = ?';
    con.query(sql, [username], (err, rows) => {
      if (err) {
        return done(err);
      }
      if (!rows.length) {
        return done(null, false, { message: 'Incorrect username.' });
      }
      const user = rows[0];
      // Compare hashed password from the database with the provided password
      bcrypt.compare(password, user.password, function(err, result) {
        if (err || !result) {
          return done(null, false, { message: 'Incorrect password.' });
        }
        // Return the user object with role information (either 'user' or 'admin')
        return done(null, { id: user.id, role: user.role });
      });
    });
  }
));
// Serialize and deserialize user for session management
passport.serializeUser(function(user, done) {
  done(null, user.id);
});
passport.deserializeUser(function(id, done) {
  // Fetch user from the database based on the id
  const sql = 'SELECT * FROM users WHERE id = ?';
  con.query(sql, [id], (err, rows) => {
    if (err) {
      return done(err);
    }
    if (rows.length === 0) {
      // If the user was not found, return an error
      return done(new Error('User not found.'));
    }
    // Check the role of the user to differentiate between user and admin
    const user = rows[0];
    if (user.role === 'user') {
      // Regular user found
      done(null, { id: user.id, role: 'user',username: user.username  });
    } else if (user.role === 'admin') {
      // Admin found
      done(null, { id: user.id, role: 'admin',username: user.username  });
    }else if (user.role === 'localuser') {
      // Admin found
      done(null, { id: user.id, role: 'localuser',username: user.username  });
    } else {
      // Unknown role, return an error
      done(new Error('Unknown user role.'));
    }
  });
});
// Middleware to check if user is authenticated before accessing protected routes
function isAuthenticated(req, res, next) {
  if (req.isAuthenticated() && (req.user.role === 'user' || req.user.role === 'admin'|| req.user.role === 'localuser')) {
    return next();
  }
  res.redirect('/login');
}
function checkRole(role) {
  return function(req, res, next) {
    // Check if the user is authenticated and has the correct role
    if (req.isAuthenticated() && req.user.role === role) {
      return next();
    }else if (req.isAuthenticated() && req.user.role === 'localuser') {
      // Redirect to the admin dashboard if the user is authenticated as an admin
      return res.redirect('/localuserdashboard');
    } else if (req.isAuthenticated() && req.user.role === 'admin') {
      // Redirect to the admin dashboard if the user is authenticated as an admin
      return res.redirect('/admindashboard');
    }else if (req.isAuthenticated() && req.user.role === 'user') {
      // Redirect to the admin dashboard if the user is authenticated as an admin
      return res.redirect('/userdashboard');
    } else {
      // User is not authenticated or doesn't have the correct role, redirect to login page
      return res.redirect('/login');
    }
  };
}
app.get('/login', (req, res) => {
  const responseData = { message: 'Welcome to the login API endpoint!' };
  res.json(responseData); // Send JSON response
});
// Catch-all route for preventing direct URL access
app.use((req, res, next) => {
  const publicRoutes = ['/login','/reset-page']; // Add other public routes here if needed
  if (req.isAuthenticated() || publicRoutes.includes(req.path)) {
    // If the user is authenticated or the route is a public route, continue to the next middleware or route handler
    return next();
  }
  // If the user is not authenticated and the route is not a public route, redirect to the login page
  res.redirect('/login');
});
// // Login route to handle user and admin logins
app.post('/login', (req, res, next) => {
  passport.authenticate('local-user', (err, user, info) => {
    if (err) {
      return res.status(500).json({ message: 'An error occurred.' });
    }

    if (!user) {
      return res.status(401).json({ message: info.message });
    }

    req.logIn(user, (err) => {
      if (err) {
        return res.status(500).json({ message: 'An error occurred.' });
      }

      let redirectUrl = '/login'; // Default redirection URL
      
      // Determine the redirection URL based on the user's role
      if (user.role === 'user') {
        redirectUrl = '/userdashboard';
      } else if (user.role === 'admin') {
        redirectUrl = '/admindashboard';
      } else if (user.role === 'localuser') {
        redirectUrl = '/localuserdashboard';
      }

      return res.json({ redirect: redirectUrl });
    });
  })(req, res, next);
});
app.get("/admincreateticket", function(req, res) {
  const getUsersQuery = "SELECT username FROM users WHERE role IN ('admin', 'user')";
  con.query(getUsersQuery, (err, users) => {
    if (err) {
      console.error('Error fetching users:', err);
      return res.status(500).json({ message: 'Error fetching users from the database.' });
    }

    // Extract usernames from the fetched user data
    const usernames = users.map(user => user.username);

    // Send the list of usernames as JSON response
    res.json({ users: usernames });
  });
});
app.get("/usercreateticket", (req, res) => {
  const getUsersQuery = "SELECT username FROM users";
  con.query(getUsersQuery, (err, users) => {
    if (err) {
      console.error('Error fetching users:', err);
      return res.status(500).json({ message: 'Error fetching users from the database.' });
    }
    // Prepare the response JSON object with users data
    const response = {
      users: users
    };
    // Send the response
    res.json(response);
  });
});

app.get("/localusercreateticket", (req, res) => {
  // Prepare the response JSON object or message
  const response = {
    message: 'Local user create ticket page.'
  };

  // Send the response
  res.json(response);
});
app.get('/chat/:ticketId', (req, res) => {
  const ticketId = req.params.ticketId;
  const role= req.user.role;
  const getMessagesQuery = 'SELECT * FROM chats WHERE ticketId = ?';
  con.query(getMessagesQuery, [ticketId], (err, rows) => {
    if (err) {
      console.error('Error fetching messages:', err);
      return res.status(500).json({ error: 'Error fetching messages from the database.' });
    }

    const messages = rows.map(row => ({
      message: row.message,
      role: row.sendBy, // Assuming you have a 'sendBy' column in your 'chats' table
      createdAt: new Date(row.createdAt).toLocaleString() // Assuming you have a 'createdAt' column in your 'chats' table
    }));

    // Return the chat messages as JSON response
    res.json({ ticketId,role, messages });
  });
});
// Set up the Socket.IO connection for a specific ticket ID
io.of('/chat/:ticketId').on('connection', (socket) => {
  const ticketId = socket.handshake.query.ticketId;
  console.log(`User connected to ticket ID: ${ticketId}`);
  
  // Define your socket event handlers for this specific ticket ID
  socket.on('message', (message) => {
    // Handle incoming messages for this ticket ID
    console.log(`Received message for ticket ID ${ticketId}: ${message}`);
    // Broadcast the message to other clients in this room, if needed
    socket.broadcast.emit('message', { message, isSent: false });
  });
  // More socket event handlers...
  // Handle disconnection
  socket.on('disconnect', () => {
    console.log(`User disconnected from ticket ID: ${ticketId}`);
    // Perform any necessary cleanup or updates related to this ticket ID
  });
  res.json({ message: 'Socket connection established for ticket ID: ' + ticketId });
});  
app.use(express.static(__dirname + '/public'));
// Convert Date to MySQL date format (YYYY-MM-DD HH:mm:ss)
function convertToMySQLDateTime(dateString) {
  const date = new Date(dateString);
  return date.toISOString().slice(0, 19).replace('T', ' ');
}
app.post("/submit", upload.single('attachment'), function(req, res) {
  const userId = req.user.id;

  // Fetch the user's username from the "users" table based on the user ID
  const userQuery = "SELECT username FROM users WHERE id = ?";
  con.query(userQuery, [userId], (userErr, userResult) => {
    if (userErr) {
      console.error('Error fetching user details:', userErr);
      return res.status(500).json({ message: 'Error fetching user details.' });
    }
    if (userResult.length === 0) {
      return res.status(404).json({ message: 'User not found.' });
    }

    const username = userResult[0].username;
    const { Description, Category, StartDate, DueDate, AssignedTo, Notes } = req.body;

    // Get the current date and time for "Created On" and "Modified On"
    const CreatedOn = convertToMySQLDateTime(new Date());
    const ModifiedOn = CreatedOn;

    // Get the uploaded file name or set it to null if no file was uploaded
    const Attachment = req.file ? req.file.filename : null;

    const CreatedBy = username;
    const ModifiedBy = username;
    const currentUserId = req.user.id;

    const query = "INSERT INTO tickets (Description, Category, StartDate, DueDate, AssignedTo, Notes, CreatedBy, CreatedOn, ModifiedBy, ModifiedOn, Attachment, CreatorId) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

    con.query(query, [Description, Category, StartDate, DueDate, AssignedTo, Notes, CreatedBy, CreatedOn, ModifiedBy, ModifiedOn, Attachment, currentUserId], (err, result) => {
      if (err) {
        console.error('Error inserting data:', err);
        return res.status(500).json({ message: 'Error inserting data into the database.' });
      }
      console.log('Data successfully inserted.');
      res.status(201).json({ message: 'Data successfully submitted to the database.' });
    });
  });
});
app.post("/userdashboard/submit", upload.single('attachment'), (req, res) => {
  const userId = req.user.id;
  const currentUserId = req.user.id;

  // Fetch the user's username from the "users" table based on the user ID
  const userQuery = "SELECT username FROM users WHERE id = ?";
  con.query(userQuery, [userId], (userErr, userResult) => {
    if (userErr) {
      console.error('Error fetching user details:', userErr);
      return res.status(500).json({ message: 'Error fetching user details.' });
    }
    if (userResult.length === 0) {
      return res.status(404).json({ message: 'User not found.' });
    }

    const username = userResult[0].username;
    const { Description, Category, Progress, StartDate, DueDate, Notes } = req.body;
    const CreatedOn = convertToMySQLDateTime(new Date());
    const ModifiedOn = CreatedOn;
    const Attachment = req.file ? req.file.filename : null;
    const ModifiedBy = username;
    const CreatedBy = username;
    const AssignedTo = username;

    const query = "INSERT INTO tickets( Description, Category, Progress, StartDate, DueDate, AssignedTo, Notes, CreatedBy, CreatedOn, ModifiedBy, ModifiedOn ,Attachment,CreatorId) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)";
    con.query(query, [Description, Category, Progress, StartDate, DueDate, AssignedTo, Notes, CreatedBy, CreatedOn, ModifiedBy, ModifiedOn, Attachment, currentUserId], (err, result) => {
      if (err) {
        console.error('Error inserting data:', err);
        return res.status(500).json({ message: 'Error inserting data into the database.' });
      }
      console.log('Data successfully inserted.');
      res.status(200).json({ message: 'Data successfully inserted.' });
    });
  });
});
app.post("/localuserdashboard/submit", upload.single('attachment'), (req, res) => {
  const userId = req.user.id;
  const currentUserId = req.user.id;

  // Fetch the user's username from the "users" table based on the user ID
  const userQuery = "SELECT username FROM users WHERE id = ?";
  con.query(userQuery, [userId], (userErr, userResult) => {
    if (userErr) {
      console.error('Error fetching user details:', userErr);
      return res.status(500).json({ message: 'Error fetching user details.' });
    }
    if (userResult.length === 0) {
      return res.status(404).json({ message: 'User not found.' });
    }
    
    const username = userResult[0].username;
    const { Description, Category, Progress, AssignedTo, Notes } = req.body;
    const CreatedOn = convertToMySQLDateTime(new Date());
    const ModifiedOn = CreatedOn;
    const Attachment = req.file ? req.file.filename : null;
    const ModifiedBy = username;
    const CreatedBy = username;

    const query = "INSERT INTO tickets( Description, Category, Progress, AssignedTo, Notes, CreatedBy, CreatedOn, ModifiedBy, ModifiedOn ,Attachment,CreatorId) VALUES (?,?,?,?,?,?,?,?,?,?,?)";
    con.query(query, [Description, Category, Progress, AssignedTo, Notes, CreatedBy, CreatedOn, ModifiedBy, ModifiedOn, Attachment, currentUserId], (err, result) => {
      if (err) {
        console.error('Error inserting data:', err);
        return res.status(500).json({ message: 'Error inserting data into the database.' });
      }

      console.log('Data successfully inserted.');
      res.status(200).json({ message: 'Data successfully inserted.' });
    });
  });
});
app.get('/register', (req, res) => {
  res.json({ message: 'Welcome to the registration endpoint.' });
});
// Route to handle user registration form submission
app.post('/register', (req, res) => {
  const { username, password, role } = req.body;
  const user= req.user.username;
  // Check if the username already exists in the database
  const checkUsernameQuery = 'SELECT * FROM users WHERE username = ?';
  con.query(checkUsernameQuery, [username], (err, rows) => {
    if (err) {
      console.error('Error checking username:', err);
      return res.status(500).json({ message: 'Error checking username in the database.' });
    }
    if (rows.length > 0) {
      // Username already exists, respond with an error message
      return res.status(400).json({ error: 'Username already exists. Please choose a different username.' });
    }

    // If the username does not exist, hash the password
    bcrypt.hash(password, 10, (err, hashedPassword) => {
      if (err) {
        console.error('Error hashing password:', err);
        return res.status(500).json({ message: 'Error hashing password.' });
      }

      // Insert the new user data into the database
      const insertUserQuery = 'INSERT INTO users (username, password, role,CreatedBy) VALUES (?, ?, ?, ?)';
      con.query(insertUserQuery, [username, hashedPassword, role,user], (err, result) => {
        if (err) {
          console.error('Error inserting user data:', err);
          return res.status(500).json({ message: 'Error inserting user data into the database.' });
        }

        console.log('New user successfully registered.');
        res.status(201).json({ message: 'New user successfully registered.' });
      });
    });
  });
});
app.get('/reset-page', (req, res) => {
  res.json({ message: 'Welcome to the password reset page.' });
});
app.post('/reset-page', (req, res) => {
  const { username, newPassword } = req.body;

  // Check if the username exists in the database
  const checkUsernameQuery = 'SELECT * FROM users WHERE username = ?';
  con.query(checkUsernameQuery, [username], (err, rows) => {
    if (err) {
      console.error('Error checking username:', err);
      return res.status(500).json({ message: 'Database error' });
    }

    if (rows.length === 0) {
      return res.status(404).json({ message: 'Username not found.' });
    }

    // Hash the new password
    bcrypt.hash(newPassword, 10, (hashErr, hashedPassword) => {
      if (hashErr) {
        console.error('Error hashing password:', hashErr);
        return res.status(500).json({ message: 'Password hashing error' });
      }

      // Update the password for the user
      const updatePasswordQuery = 'UPDATE users SET password = ? WHERE username = ?';
      con.query(updatePasswordQuery, [hashedPassword, username], (updateErr) => {
        if (updateErr) {
          console.error('Error updating password:', updateErr);
          return res.status(500).json({ message: 'Password update error' });
        }
        res.json({ message: 'Password updated successfully.' });
      });
    });
  });
});
//Route to display the user dashboard
app.get('/userdashboard', isAuthenticated, checkRole('user'), nocache(), (req, res) => {
  const filterOption = req.query.filterOption;
  const progress = req.query.Progress; // Access the "Progress" value from the form
  const username = req.user.username; // Get the username of the logged-in user
  // Construct the SQL query to fetch tickets assigned to the logged-in user
  let sql = 'SELECT * FROM tickets WHERE AssignedTo = ?';
  // Add a condition to filter by "Progress" if a value is selected in the dropdown
  if (progress) {
    sql += ' AND Progress = ?';
  }
  con.query(sql, [username, progress], (err, rows) => {
    if (err) {
      console.error('Error fetching data:', err);
      return res.status(500).json({ message: 'Error fetching data from the database.' });
    }
    res.json({ tickets: rows, filterOption: progress, username });
  });
});
// Route to display the admin dashboard
app.get('/admindashboard', isAuthenticated, checkRole('admin'), nocache(), (req, res) => {
  const userId = req.query.Id;
  const username = req.user.username;
  const filterOption = req.query.filterOption;
  const progress = req.query.Progress;

  // If a user ID is provided, fetch the user based on the ID from the database
  if (userId) {
    const sql = 'SELECT * FROM tickets WHERE Id = ?';
    con.query(sql, [userId], (err, rows) => {
      if (err) {
        console.error('Error fetching data:', err);
        return res.status(500).json({ message: 'Error fetching data from the database.' });
      }
      res.json({ tickets: rows, username });
    });
  } else {
    // If no user ID is provided, fetch all tickets from the database with filter
    let sql = 'SELECT * FROM tickets';
    // Add a condition to filter by "Progress" if a value is selected in the dropdown
    if (progress) {
      sql += ' WHERE Progress = ?';
    }
    con.query(sql, [progress], (err, rows) => {
      if (err) {
        console.error('Error fetching data:', err);
        return res.status(500).json({ message: 'Error fetching data from the database.' });
      }
      res.json({ tickets: rows, filterOption: progress, username });
    });
  }
});
app.get('/localuserdashboard', isAuthenticated, checkRole('localuser'), nocache(), (req, res) => {
  const userId = req.query.Id;
  const filterOption = req.query.filterOption;
  const username = req.user.username;
  const progress = req.query.Progress; // Access the "Progress" value from the form
  const currentUserId = req.user.id;

  // If a user ID is provided, fetch the user based on the ID from the database
  if (userId) {
    const sql = 'SELECT * FROM tickets WHERE Id = ? AND CreatorId = ?';
    con.query(sql, [userId, currentUserId], (err, rows) => {
      if (err) {
        console.error('Error fetching data:', err);
        return res.status(500).json({ message: 'Error fetching data from the database.' });
      }
      res.json({ tickets: rows, username });
    });
  } else {
    // If no user ID is provided, fetch tickets created by the same user with filter
    let sql = 'SELECT * FROM tickets WHERE CreatorId = ?';

    // Add a condition to filter by "Progress" if a value is selected in the dropdown
    if (progress) {
      sql += ' AND Progress = ?';
    }
    con.query(sql, [currentUserId, progress], (err, rows) => {
      if (err) {
        console.error('Error fetching data:', err);
        return res.status(500).json({ message: 'Error fetching data from the database.' });
      }
      res.json({ tickets: rows, filterOption: progress, username });
    });
  }
});
app.get('/edit/:id', (req, res) => {
  const ticketId = req.params.id;
  
  // Fetch the ticket data from the database for the specific ticketId
  const sql = 'SELECT * FROM tickets WHERE Id = ?';
  con.query(sql, [ticketId], (err, rows) => {
    if (err) {
      console.error('Error fetching ticket data:', err);
      return res.status(500).json({ message: 'Error fetching ticket data from the database.' });
    }
    
    // Fetch the names from the users table
    const userQuery = "SELECT username FROM users WHERE role IN ('admin', 'user')";
    con.query(userQuery, (userErr, users) => {
      if (userErr) {
        console.error('Error fetching user names:', userErr);
        return res.status(500).json({ message: 'Error fetching user names from the database.' });
      }
      
      console.log('Users fetched successfully:', users);
      
      // Prepare the response JSON object with ticket data and user names
      const response = {
        ticket: rows[0],
        users: users
      };
      
      // Send the response
      res.json(response);
    });
  });
});
app.get('/useredit/:id', (req, res) => {
  const ticketId = req.params.id;
  
  // Fetch the ticket data from the database for the specific ticketId
  const sql = 'SELECT * FROM tickets WHERE Id = ?';
  con.query(sql, [ticketId], (err, rows) => {
    if (err) {
      console.error('Error fetching ticket data:', err);
      return res.status(500).json({ message: 'Error fetching ticket data from the database.' });
    }
    
    if (rows.length === 0) {
      return res.status(404).json({ message: 'Ticket not found.' });
    }

    // Return the ticket data in the response
    res.status(200).json({ ticket: rows[0] });
  });
});
app.post('/update/:id', upload.single('attachment'), (req, res) => {
  const ticketId = req.params.id;
  const userId = req.user.id;

  // Fetch the user's username from the "users" table based on the user ID
  const userQuery = "SELECT username FROM users WHERE id = ?";
  con.query(userQuery, [userId], (userErr, userResult) => {
    if (userErr) {
      console.error('Error fetching user details:', userErr);
      return res.status(500).json({ message: 'Error fetching user details.' });
    }
    if (userResult.length === 0) {
      return res.status(404).json({ message: 'User not found.' });
    }
    
    const username = userResult[0].username;
    const { Description, Category, StartDate, AssignedTo, Notes, DueDate } = req.body;
    const ModifiedOn = convertToMySQLDateTime(new Date());
    const attachment = req.file ? req.file.filename : (req.body.attachment || '');
    
    let sql = 'UPDATE tickets SET ModifiedBy = ?, ModifiedOn = ?';
    const values = [username, ModifiedOn];
    
    if (Description) {
      sql += ', Description = ?';
      values.push(Description);
    }
    if (Category) {
      sql += ', Category = ?';
      values.push(Category);
    }
    if (AssignedTo) {
      sql += ', AssignedTo = ?';
      values.push(AssignedTo);
    }
    if (Notes) {
      sql += ', Notes = ?';
      values.push(Notes);
    }
    if (DueDate) {
      sql += ', DueDate = ?';
      values.push(DueDate);
    }
    if (StartDate) {
      sql += ', StartDate = ?';
      values.push(StartDate);
    }
    if (attachment) {
      sql += ', attachment = ?';
      values.push(attachment);
    }
    
    sql += ' WHERE Id = ?';
    values.push(ticketId);
    
    // Update the ticket data in the database
    con.query(sql, values, (err, result) => {
      if (err) {
        console.error('Error updating data:', err);
        return res.status(500).json({ message: 'Error updating data in the database.' });
      }
      
      console.log('Data successfully updated.');
      res.status(200).json({ message: 'Data successfully updated.' });
    });
  });
});
app.post('/userdashboard/update/:id', upload.single('attachment'), (req, res) => {
  const ticketId = req.params.id;
  const userId = req.user.id;

  // Fetch the existing attachment from the database
  const getAttachmentQuery = "SELECT attachment FROM tickets WHERE Id = ?";
  con.query(getAttachmentQuery, [ticketId], (getAttachmentErr, getAttachmentResult) => {
    if (getAttachmentErr) {
      console.error('Error fetching existing attachment:', getAttachmentErr);
      return res.status(500).json({ message: 'Error fetching existing attachment from the database.' });
    }

    // Fetch the user's username from the "users" table based on the user ID
    const userQuery = "SELECT username FROM users WHERE id = ?";
    con.query(userQuery, [userId], (userErr, userResult) => {
      if (userErr) {
        console.error('Error fetching user details:', userErr);
        return res.status(500).json({ message: 'Error fetching user details.' });
      }
      if (userResult.length === 0) {
        return res.status(404).json({ message: 'User not found.' });
      }
      
      const username = userResult[0].username;
      const { Progress, AssignedTo, Notes } = req.body;

      // Get the current date and time for "Modified On"
      const ModifiedOn = convertToMySQLDateTime(new Date());
      const attachment = req.file ? req.file.filename : (req.body.attachment || getAttachmentResult[0].attachment || '');
      const ModifiedBy = username;

      // Update the ticket data in the database
      const sql = 'UPDATE tickets SET Progress = ?, Notes = ?, ModifiedBy = ?, ModifiedOn = ?, attachment = ? WHERE Id = ?';
      con.query(sql, [Progress, Notes, ModifiedBy, ModifiedOn, attachment, ticketId], (err, result) => {
        if (err) {
          console.error('Error updating data:', err);
          return res.status(500).json({ message: 'Error updating data in the database.' });
        }
        console.log('Data successfully updated.');
        res.status(200).json({ message: 'Data successfully updated.' });
      });
    });
  });
});
// Route to handle logout
app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ message: 'Error occurred during logout.' });
    }
    res.json({ message: 'Logout successful.' });
  });
});
const serverPort = 4000;
server.listen(serverPort, () => {
  console.log(`Server listening on port ${serverPort}`);
});
module.exports =app ;
