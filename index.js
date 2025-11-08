
require('dotenv').config();
const express = require('express');
const app = express();
const bodyParser = require('body-parser');
const { MongoClient, ObjectId } = require('mongodb');
const cors = require("cors");
const uuid = require('uuid');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const compression = require('compression');
const cookieParser = require('cookie-parser'); 
const { emit, send, title, exit } = require('process');
const { arrayBuffer } = require('stream/consumers');
const  {SendVerifCode,SendBookigNotificationMail, ReplayToContact,SendAbonnement} = require('./send_mails'); 
const {redis,createClient} = require('redis');
const {getProductsCache,saveProductsInCache ,Getmakeups  ,getSpecifyProducts, saveClientsCash,getClientsCash} = require('./redis')
const  {  v4: uuidv4  } = require("uuid")  // Generate unique session IDs
const server = require("http").createServer(app);
const useragent = require("useragent");
const { link } = require('fs');
const { subscribe } = require('diagnostics_channel');
const FRONT = process.env.FRONT_END_URL

const io = require("socket.io")(server, {
  cors: {
      origin: [
          process.env.FRONT, 
          'https://alltunisiapara.com',
          'https://www.alltunisiapara.com'
      ].filter(Boolean), // Removes any undefined/null values
      credentials: true,
      methods: ["GET", "POST"]
  }
});

// APP use
app.use(cors({
    origin:  [
      process.env.FRONT, 
      'https://alltunisiapara.com',
      'https://www.alltunisiapara.com'
  ].filter(Boolean), 
    methods: ["GET", "POST"],        
    credentials: true         ,
    secure : process.env.NODE_ENV == "production"       
}));
app.use(cookieParser());
// Load environment variables
app.use(compression());
const dbName = process.env.DBNAME;
const USERS_COLLECTION = process.env.USERS_COLLECTION;
const JWT_SECRET_KEY = process.env.JWT_SECRET_KEY;

const ACCESS_SECRET = process.env.ACCESS_SECRET;
const REFRESH_SECRET = process.env.REFRESH_SECRET;
const REPPORTS = process.env.REPPORTS_COLLECTION;
const PRODUCTS_COLLECTION = process.env.PRODUCTS_COLLECTION
const ADMIN_COLLECTION = process.env.ADMIN_COLLECTION;
const APPCOLLECTION = process.env.APPCOLLECTION
const MessagesCollection = process.env.MESSAGES;
const ORDERS_COLLECTION = process.env.ORDERS_COLLECTION;
const NOTIFICATIONS_COLLECTION = process.env.NOTIFICATIONS
const LINK_COLLECTION = process.env.LINK_COLLECTION
const SALES_COLLECTION = process.env.SALES_COLLECTION
const RECIP_COLLECTION = process.env.RECIP_COLLECTION
const BLOGS_COLLECTION = process.env.BLOGS_COLLECTION
const Reviews_Collection = process.env.Reviews_Collection
const EXPENESS_COLLECTION = process.env.EXPENESS_COLLECTION
const BRANDS = process.env.BRANDS;
const uri  = process.env.MONGO_URI;


async function run() {
  try {
    // Connect the client to the server	(optional starting in v4.7)
    await client.connect();
    // Send a ping to confirm a successful connection
    await client.db("admin").command({ ping: 1 });
    console.log("Pinged your deployment. You successfully connected to MongoDB!");
  } finally {
    // Ensures that the client will close when you finish/error
    await client.close();
  }
}

const client = new MongoClient(uri);
let db =client.db(dbName);

async function connectDB() {
    try {
        await client.connect();
        db = client.db(dbName);
        console.log("Connected to MongoDB");
    } catch (err) {
        console.error("Error connecting to database:", err);
        process.exit(1); // Exit if unable to connect
    }
}
const U = process.env.REDIS_URL

connectDB();

//const redis_client = redis.createClient();
//redis_client.connect().catch(console.error);



const redis_client = createClient({
    username: 'default',
    password: process.env.REDIS_PASS,
    socket: {
        host: process.env.REDIS_URL,
        port: 16921
    }
});

  // >>> bar
const RED = async()=>{
  redis_client.on('error', err => console.log('Redis Client Error', err));

await redis_client.connect();

await redis_client.set('foo', 'bar');
const result = await redis_client.get('foo');
console.log(result)
}
RED()
const port = process.env.PORT || 5000;
app.use(bodyParser.json());
// Functions
const SaveMSg = async (data) => {
    try {
      const collection = db.collection(MessagesCollection);
      const fetch = await collection.findOne({ id: data.id });
  
      // If the message with the given ID exists, update the document by pushing the new message
      if (fetch) {
        // Update the existing document by pushing the new message
        await collection.updateOne(
          { id: data.id },
          {
            $push: {
              messages: {
                msg: data.msg,
                sender: "user",
                date : data.date
              },
            },
          }
        );
        console.log("Message added to the array successfully");
      } else {
        // If no document exists, insert a new one
        await collection.insertOne({
          id: data.id,
          messages: [
            {
              msg: data.msg,
              sender: "user",
              date : data.date
            },
          ],
        });
        console.log("Message inserted successfully");
      }
  
      return true;
    } catch (err) {
      console.log(err);
      return false;
    }
  };
  
  const SaveAdMSg = async (data) => {
    try {
      const collection = db.collection(MessagesCollection);
      const fetch = await collection.findOne({ id: data.receiver });
  console.log('fetch :' , fetch);
      // If the message with the given ID exists, update the document by pushing the new message
      if (fetch) {
        // Update the existing document by pushing the new message
        await collection.updateOne(
          { id: data.receiver },
          {
            $push: {
              messages: {
                msg: data.msg,
                sender: "admin",
                date : data.date
              },
            },
          }
        );
        console.log("Message added to the array successfully");
      } else {
        // If no document exists, insert a new one
        await collection.insertOne({
          id: data.receiver,
          messages: [
            {
              msg: data.msg,
              sender: "admin",
              date : data.date
            },
          ],
        });
        console.log("Message inserted successfully");
      }
  
      return true;
    } catch (err) {
      console.log(err);
      return false;
    }
  };

const hashPassword = async (password) => {
    const saltRounds = 13; // Higher values are more secure but slower
    const salt = await bcrypt.genSalt(saltRounds);
    return await bcrypt.hash(password, salt);
};
const comparePassword = async (password, hashedPassword) => {
    return await bcrypt.compare(password, hashedPassword);
}
const generateTokens = (userId) => {
    // Access token (expires in 15 minutes)
    const accessToken = jwt.sign({ userId }, JWT_SECRET_KEY, { expiresIn: '15m' });
    // Refresh token (expires in 30 days)
    const refreshToken = jwt.sign({ userId }, JWT_SECRET_KEY, { expiresIn: '30d' });

    return { accessToken, refreshToken };
};
// Middleware to authenticate access tokens
const authenticateToken = (req, res, next) => {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) return res.status(401).json({ error: "Unauthorized" });

    jwt.verify(token, ACCESS_SECRET, (err, decoded) => {
        if (err) return res.status(403).json({ error: "Invalid token" });
        req.userId = decoded.id;
        next();
    });
};

const GET_USER_BY_EMAIL = async (email) => {
    try {
        const collection = db.collection(USERS_COLLECTION);
        return await collection.findOne({ email: email });
    } catch (err) {
        console.error("Error getting user by email:", err);
        return null;
    }
};
const GET_USER_BY_Token = async (Token) => {
    try {
        const collection = db.collection(USERS_COLLECTION);
        return await collection.findOne({ token: Token });
    } catch (err) {
        console.error("Error getting user by Token:", err);
        return null;
    }
};
const is_acrive_user = async (email) =>{
    try{
const fetch = await db.collection(USERS_COLLECTION).findOne({email : email});
return fetch.active;
    }catch(err){
        console.log('if acrive user error ! ', err);
    }
}

const getUserByID= async(id)=>{
    try{
const Fetch = await db.collection(USERS_COLLECTION).findOne({_id :new ObjectId(id)});

return Fetch;
    }catch(err){
        console.log('error fetching by id :', err);
        return null;
    }
}
const updateUserInfo = async (data) => {
    try {
        const {  email, items} = data;
console.log(data)
        const collection = db.collection(USERS_COLLECTION);

      
   const updateResult=     await collection.updateOne(
            { email: email },
            {
              $push: {
                orders: items
              },
            }
          );

        return updateResult.modifiedCount > 0;
    } catch (err) {
        console.error("Error updating user info:", err);
        return false;
    }
};
const SaveNotificationFct = async(data)=>{
    try{
const Task = await db.collection(NOTIFICATIONS_COLLECTION).insertOne(data);
return true;
    }catch(err){
        console.log(err);
        return false
    }
}
const UpdateUSER_SALES = async(id,email)=>{
  try{
    
const findOrder = await db.collection(SALES_COLLECTION).find().toArray();

let G = {};
findOrder.forEach((i)=>{
  if(i.purchases.id === id){
    console.log(i);
    G = i;
  }

})
if(findOrder){
  const collection = db.collection(USERS_COLLECTION);

  const updateResult = await collection.updateOne(
    { email: email },
    {
      
        $push: {
          purchases: G
          }
          }
          );

          if(updateResult.modifiedCount>=0 ){
          return 1
}
}

  }catch(err){
    console.log(err);
  }
}
const getOrderByID  = async(id)=>{
  try{
const data = await db.collection(ORDERS_COLLECTION).findOne({_id : new ObjectId(id)});
if(data){
  return data
}else{
  return []
}
  }catch(err){
    return null
  }
}
const ReturnData = async (array) => {
  try {
    const sendingPromises = array.map(async (item) => {
      const data = await getOrderByID(item.purchases.id);
      return {
        status: item.purchases.status,
        data: data,
      };
    });

    const sending = await Promise.all(sendingPromises); // Wait for all promises to resolve
    return sending;
  } catch (err) {
    console.log('got : ', err);
    return [];
  }
};
const CalculateRevenu = async(array) => {
  let totalRevenu = 0;

  try {
    array.forEach((order) => {
      let items;

      // Ensure `items` is an array before using `reduce`
      if (typeof order.data.items === "string") {
        items = JSON.parse(order.data.items);
      } else {
        items = order.data.items;
      }

      // Calculate the total for the current order
    items.forEach((item)=>{
      const Totla = item.quantity * item.current_price;
      totalRevenu += Totla;
    })
    let s = 0;
  
    const t = order.data.utiliste * order.data.merci
    s += t;
totalRevenu = totalRevenu - s


    });

    return totalRevenu.toFixed(2);
  } catch (err) {
    console.error("Error in CalculateRevenu:", err);
    return 0;
  }
};
const CalculateExpensess = async ()=> {
  try {
    const products = await db.collection(PRODUCTS_COLLECTION).find().toArray();
    
    // Calculate total cost using reduce
    const cost = products.reduce((acc, product) => acc + (product.cost * product.stock), 0);


    return cost;
  } catch (err) {
    console.error("Error calculating expenses:", err);
    return 0; // Return 0 if there is an error
  }
};

const getItemCatByID = async(id)=>{
  try{
const Fetch = await db.collection(PRODUCTS_COLLECTION).findOne({_id : new ObjectId(id)});
if(Fetch){
  return Fetch.Categorie;
}
  }catch(err){
    console.log(err)
    return [];
  }
}
const getItemBrandByID = async(id)=>{
  try{
const Fetch = await db.collection(PRODUCTS_COLLECTION).findOne({_id : new ObjectId(id)});
if(Fetch){
  return Fetch.marques;
}
  }catch(err){
    console.log(err)
    return [];
  }
}
const FilterByCategorie = async (array) => {
  try {
    const categories = [
      { name: "Visage", value: 0 },
      { name: "cheveau", value: 0 },
      { name: "Corps", value: 0 },
      { name: "Bébé et Maman", value: 0 },
      { name: "Compléments Alimentaires", value: 0 },
      { name: "Hygiène", value: 0 },
      { name: "Solaire", value: 0 },
      { name: "Bio et Nature", value: 0 },
      { name: "Matériels Médical", value: 0 },
      { name: "Homme", value: 0 },
      { name: "Nutrition Sportive", value: 0 },
      { name: "Animalerie", value: 0 },
    ];

    let items = [];
    
    // Push items from array into 'items'
    array.forEach((item) => {
      items.push(JSON.parse(item.data.items));
    });

    // Map through items and process them asynchronously
    await Promise.all(items.map(async (item) => {
      await Promise.all(item.map(async (i) => {
        const Categorie = await getItemCatByID(i.id);
   

        categories.forEach((cat) => {
          if (cat.name.toLocaleLowerCase() === Categorie?.toLocaleLowerCase()) {
         
            cat.value += i.quantity; // Increment the category value by item quantity
          }
        });
      }));
    }));

    return categories;
  } catch (err) {
    console.log(err);
    return [];
  }
};
const FilterByGendre = async (array) => {
  try {
    const Genders = [
      { name: 'Male', value: 0 },
      { name: 'Female', value: 0 }
    ];

    let totalQuantity = 0;

    // Calculate total quantity and gender-specific quantities
    array.forEach((item) => {
      const gender = item.data.gen.toLocaleLowerCase();
      const quantities = JSON.parse(item.data.items);
      
      const totalGenderQuantity = quantities.reduce((acc, i) => acc + i.quantity, 0);
      
      if (gender === "male") {
        Genders.find(g => g.name === "Male").value += totalGenderQuantity;
      } else if (gender === "female") {
        Genders.find(g => g.name === "Female").value += totalGenderQuantity;
      }

      totalQuantity += totalGenderQuantity;
    });

    // Calculate percentages
    if (totalQuantity > 0) {
      Genders.forEach((gender) => {
        gender.value = ((gender.value / totalQuantity) * 100).toFixed(2); // Calculate percentage
      });
    }

    return Genders;
  } catch (err) {
    console.log(err);
    return [];
  }
};

const FilterByState = async (array) => {
  try {
    // Step 1: Filter only "Delivered" orders



    // Step 2: Count occurrences of each "ville"
    const cityCounts = {};
    array.forEach(order => {
      const city = order.data.etat.toLowerCase(); // Normalize to lowercase
      cityCounts[city] = (cityCounts[city] || 0) + 1;
    });

    // Step 3: Calculate percentage per city
    const totalDelivered = array.length;
    const percentageByCity = Object.keys(cityCounts).map(city => ({
      etat: city,
      percentage: ((cityCounts[city] / totalDelivered) * 100).toFixed(2) + "%" // Format as percentage
    }));

    return percentageByCity;
  } catch (err) {
    console.log(err);
    return [];
  }
};
const Fil = async (array, all, id) => { 
  try {
    // Combine the tags into one filtered array
    const result = array.reduce((acc, tag) => {
      const tagData = all.filter((item) => item.tags.includes(tag));
      acc.push(...tagData);  // Flatten the data directly into the accumulator
      return acc;
    }, []);

    


    return result;
  } catch (err) {
    console.error(err);
    return [];
  }
}


const formatDate101 = (date) => {
  const formattedDate = date.toLocaleString('en-US', {
    month: 'numeric',
    day: 'numeric',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    hour12: false, // Use 24-hour format
  });

  const [datePart, timePart] = formattedDate.split(', ');

  // Ensure all times after midnight are displayed as 00:xx
  const adjustedTime = timePart.startsWith('24:') 
    ? timePart.replace('24:', '00:') // This line is redundant because toLocaleString never produces '24:'
    : timePart;

  return `${datePart}, ${adjustedTime}`;
};

const updateStockage = async(ids) =>{
  try{
    ids.forEach( async (item)=>{
      const qts = item.quantity;
      const oldS = await db.collection(PRODUCTS_COLLECTION).findOne({_id : new ObjectId(item.id)})

      newS = Number(oldS.stock) - qts > 0 ? Number(oldS.stock) - qts : qts;

      await db.collection(PRODUCTS_COLLECTION).updateMany({_id : new ObjectId(item.id)}, {$set :{newstock : newS, sold : qts}})
     })
return true;
  }catch(err){

    return null;
  }
}

const ByBrandsfct = async (array) => {
  try {
    const brandMap = new Map(); // Store brand counts efficiently

    // Extract and parse all items from the input array
    const items = array.flatMap(item => JSON.parse(item.data.items));

    // Process each item
    await Promise.all(
      items.map(async (i) => {
        const Brand = await getItemBrandByID(i.id);

        // Update count in the brandMap
        brandMap.set(Brand, (brandMap.get(Brand) || 0) + i.quantity);
      })
    );

    // Convert Map to an array of objects
    const Brands = Array.from(brandMap, ([name, value]) => ({ name, value }));

    // Calculate total quantity
    const totalQuantity = Brands.reduce((sum, brand) => sum + brand.value, 0);
console.log(Brands,totalQuantity)
    return { Brands, totalQuantity };
  } catch (err) {
    console.log(err);
    return { Brands: [], totalQuantity: 0 };
  }
};
const GetThisSalesbyU = async (userId, purchases) => {
  try {
    // Fetch user's orders and filter confirmed ones
    const orders = await db.collection(ORDERS_COLLECTION)
      .find({ auth: userId })
      .toArray();
    const confirmedOrders = orders.filter(order => order.status === "confirmed");

    // Extract delivered purchase IDs (using correct status spelling)
    const deliveredOrderIds =[];
    purchases.forEach(purchase => {
      if (purchase.purchases?.status === "Dilivired") { // Optional chaining in case purchases is undefined
        deliveredOrderIds.push(purchase.purchases.id); // Ensure ID is string for comparison
      }
    });

    // Filter confirmed orders with matching delivered IDs (using MongoDB '_id')
    const sales = confirmedOrders.filter(order => 
      deliveredOrderIds.filter((item)=>item == order._id) // Convert ObjectId to string
    );
  


    return { orders, sales };
  } catch (err) {
    console.error("Error in GetThisSalesbyU:", err);
    return { error: err.message }; // Better error handling
  }
};
const fetchUsers404 = async () => {
  try {
    // Fetch all messages
    const LSG = await db.collection(MessagesCollection).find().toArray();

    // Extract unique user IDs and their last messages
    const uniqueUserMap = new Map(); // Use a Map to ensure uniqueness
    LSG.forEach((item) => {
      if (!uniqueUserMap.has(item.id)) {
        uniqueUserMap.set(item.id, {
          id: item.id,
          lastMSG: item.messages[item.messages.length - 1], // Get the last message
        });
      }
    });

    // Convert Map values to an array of unique users
    const uniqueUsers = Array.from(uniqueUserMap.values());

    // Fetch user details in parallel
    const users = await Promise.all(
      uniqueUsers.map(async (item) => {
        const user = await db.collection(USERS_COLLECTION).findOne({
          _id: new ObjectId(item.id),
        });

        if (user) {
          return {
            user: { name: user.name, _id: user._id, pdf: user.pdf },
            lastMSG: item.lastMSG,
          };
        }
        return null; // Handle cases where the user might not exist
      })
    );

    // Filter out null values (users that no longer exist)
    const filteredUsers = users.filter((user) => user !== null);


    return filteredUsers;
  } catch (err) {
    console.error("Error fetching users:", err);
    return [];
  }
};
const GetExp = async()=>{
  try{
const data = await db.collection(EXPENESS_COLLECTION).find().toArray();
console.log(data)
return data
  }catch(err){
    console.log(err)
    return [];
  }

}
app.post('/update_Sales_status',async(req,res)=>{
  try {
    const { orderID, status } = req.body;


    const filter = await db.collection(SALES_COLLECTION).find().toArray();
    const find = filter.map(async(item)=>{
      if(item.purchases.id === req.body.orderID){
        
        await db.collection(SALES_COLLECTION).updateOne(
          { _id: new ObjectId(item._id) }, 
          { $set: { "purchases.status": status } } 
        )}})


  
    const order = await db.collection(ORDERS_COLLECTION).findOne(
      { _id: new ObjectId(orderID) },
      { projection: { auth: 1, items: 1 } }
    );



  
    const productIds = JSON.parse(order.items).map(item => new ObjectId(item.id));
    const products = await db.collection(PRODUCTS_COLLECTION)
      .find({ _id: { $in: productIds } })
      .toArray();
const updateStocke  = await updateStockage(JSON.parse(order.items));
   
   

    // 4. Update user points atomically
 if(order.auth != "undefined" && order.auth){
  const totalPoints = products.reduce((sum, product) => sum + (Number(product.point) || 0), 0);
  const userUpdate = await db.collection(USERS_COLLECTION).updateOne(
    { _id: new ObjectId(order.auth) },
    { 
      $inc: { "pts.pts": totalPoints },
      $setOnInsert: { "pts.used": 0 }
    },
    { upsert: true }
  );

 }
    res.json({
      message: true});

  } catch (err) {
    console.error("Update Error:", err);
    res.status(500).json({
      success: false,
      message: "Server error during update",
      error: err.message
    });
  }
})
// POST REQUESTS 
// Register Route
app.post("/register", async (req, res) => {
    try {
        
        
        const collection = db.collection(USERS_COLLECTION);
        const existingUser = await GET_USER_BY_EMAIL(req.body.email);

        if (!existingUser) {
            const verificationCode = Math.floor(10000 + Math.random() * 90000).toString();

           
const verificationToken = uuid.v4();
            const hashedPassword = await hashPassword(req.body.pass);
            const newUser = {
                name: req.body.full_name,
                email: req.body.email,
                password: hashedPassword,
                active: false,
                pdf: "https://res.cloudinary.com/dbbc3ueua/image/upload/v1742133592/fwf8e0fewfifkmbgpjue.png",
                tel: req.body.tel,
                code : verificationCode,
                token : verificationToken,
                purchases : [],
                orders : [],
                Fav : [],
                pts : {pts  :0 , used : 0},
                memberSens : formatDate101(new Date()),
                messages : [],
                sub : true,
            };

            const result = await collection.insertOne(newUser);
            await SendVerifCode(req.body.email,req.body.full_name,verificationCode,verificationToken);
            await saveClientsCash();
            return res.json({ message: true , token : verificationToken});
        } else {
            return res.status(200).json({ message: false });
        }
    } catch (err) {
        console.error("Error in register route:", err);
        res.status(500).json({ error: "Internal Server Error" });
    }
});

// Login Route
app.post("/login", async (req, res) => {
    const { email, password } = req.body;

    try {
        const user = await db.collection(USERS_COLLECTION).findOne({email : email });
        
         

        if (user && await bcrypt.compare(password, user.password)) {
            const Check =  await is_acrive_user(email);
 
            if(Check == false){
                res.json({token : user.token});
            }else{
                const accessToken = jwt.sign({ id: user._id }, ACCESS_SECRET, { expiresIn: "15m" });
                const refreshToken = jwt.sign({ id: user._id }, REFRESH_SECRET, { expiresIn: "30d" });
    
                res.cookie("refreshToken", refreshToken, {
                    httpOnly: true,
                    secure: process.env.NODE_ENV === "production",
                    sameSite: "Strict",
                });
    console.log('login succefully')
                res.json({ accessToken });
            }
        } else {
            res.status(400).json({ error: "Invalid credentials" });
        } 
    } catch (error) {
        console.error("Login error:", error);
        res.status(500).json({ error: "Internal Server Error" });
    }
});


app.post('/saveFavorit',async(req,res)=>{
  try{
const Up = await db.collection(USERS_COLLECTION).updateOne({_id : new ObjectId(req.body.id)},{$set : {Fav : req.body.Fav}});
res.json({message : true})

  }catch(err){
    res.json({message : err})
  }
})

app.post("/admin_login", async (req, res) => {
  const { email, password, code } = req.body;

  try {
    // Find the admin user by email

    const admin = await db.collection(ADMIN_COLLECTION).findOne({ email });

    if (!admin || !(await bcrypt.compare(password, admin.password))) {
      return res.status(400).json({ error: "Invalid credentials" });
    }

    if (admin.role !== "admin") {
      return res.status(403).json({ error: "Unauthorized access" });
    }

    if (!(await bcrypt.compare(code, admin.pinCodeHash))) {
      return res.status(400).json({ error: "Invalid pin code" });
    }

    // Parse the user-agent header for device information
    const agent = useragent.parse(req.headers["user-agent"]);

    // Get the real client IP address
    let ip = req.headers["x-forwarded-for"] || req.connection.remoteAddress;
    if (ip && ip.startsWith("::ffff:")) {
      ip = ip.substr(7); // Clean IPv6 format for local network
    }

    const sessionId = uuidv4(); // Generate unique session ID


    const newDevice = {
      sessionId,
      ip,
      browser: agent.family,
      os: agent.os.family,
      device: agent.device.family  || "Unknown", // Default to "Unknown" if device is not detected
      loginAt: new Date(),
    };

    // Store the new device session in the admin's device array
    await db.collection(ADMIN_COLLECTION).updateOne(
      { _id: admin._id },
      { $push: { devices: newDevice } } // Push new session to devices array
    );

    // Generate JWT access and refresh tokens
    const accessToken = jwt.sign({ id: admin._id, role: admin.role }, ACCESS_SECRET, { expiresIn: "15m" });
    const refreshToken = jwt.sign({ id: admin._id, sessionId }, REFRESH_SECRET, { expiresIn: "30d" });

    // Store refresh token in Redis with session expiration of 30 days
    await redis_client.set(`refresh:${admin._id}:${sessionId}`, refreshToken, "EX", 30 * 24 * 60 * 60);

    // Set HttpOnly, Secure and SameSite cookie for refresh token
    res.cookie("refreshToken1", refreshToken, {
      httpOnly: true, // Ensures the cookie is only accessible by the server
      secure: process.env.NODE_ENV === "production", // Ensures cookie is sent over HTTPS in production
      sameSite: "Strict", // Prevents cross-site request forgery (CSRF)
    });

    console.log(`✅ Admin logged in. Session ID: ${sessionId}, IP: ${ip}, Device: ${newDevice.device}`);

    // Send access token to the client
    res.json({ accessToken });

  } catch (error) {
    console.error("❌ Admin login error:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

app.get('/devices/:adminId', async (req, res) => {
  const { adminId } = req.params;
  try {
    const admin = await db.collection(ADMIN_COLLECTION).findOne({ _id: new ObjectId(adminId) });

    if (!admin) {
      return res.status(404).json({ error: "Admin not found" });
    }

    res.json({ devices: admin.devices || [] });
  } catch (error) {
    console.error('Error fetching devices:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});
app.get('/allblogs',async(req,res)=>{
  try{
const r = await db.collection(BLOGS_COLLECTION).find().toArray();

res.json({message : r})
  }catch(err){
    console.log(err)
    res.json({message : []})
  }
})
app.get('/legals101',async(req,res)=>{
  try{

    const i =await db.collection(APPCOLLECTION).findOne({id : "setup"});
  
    res.json({message : true , dt : [{g : i.Gratuit , p : i.merci }]})
  }catch(err){
    console.log(err)
    res.json({message : false , dt : [{g : 'X' , p : '0'}]})
  }
})
app.get('/gymPR',async(req,res)=>{
  try{
const result = await getSpecifyProducts('nutrition Sprotive')
res.json({message : result})
  }catch(err){
    console.log(err)
    res.json({message : [], error : err})
  }
})
app.get('/Analyse',async(req,res)=>{
  try{


    const purch = await db.collection(SALES_COLLECTION).find().toArray();

    const Sending = await ReturnData(purch);
    const ByCategorie = await FilterByCategorie(Sending.filter((item)=>{
      return item.status == "Dilivired"
    }))
    const ByGendre = await FilterByGendre(Sending.filter((item)=>{
      return item.status == "Dilivired"
    }))
    const ByState = await FilterByState(Sending.filter((item)=>{
      return item.status == "Dilivired"
    }))
    const ByBrands = await ByBrandsfct(Sending.filter((item)=>{
      return item.status == "Dilivired"
    }))
const Expensess= await GetExp()

    res.json({General : Sending, CategorieCal : ByCategorie ,Gen: ByGendre , State: ByState ,Brands : ByBrands,Exp : Expensess})



  }catch(err){
    console.log(err);
    res.json({message : err});
  }
})
app.get('/AnalyseDh',async(req,res)=>{
  try{


    const purch = await db.collection(SALES_COLLECTION).find().toArray();

    const Sending = await ReturnData(purch);
  


    res.json({General : Sending})



  }catch(err){
    console.log(err);
    res.json({message : err});
  }
})

app.get('/getLinks',async(req,res)=>{
  try{
const requiredData = await db.collection(LINK_COLLECTION).find().toArray();
const ids = [
  'visage',
  'cheveau',
  'corps',
  'bebe-maman',
  'complements-alimentaires',
  'hygiene',
  'solaire',
  'bio-nature',
  'materiels-medical',
  'homme'
];

const images = await db.collection(APPCOLLECTION).find().toArray();
const r = images.filter((img)=>ids.includes(img.id))

res.json({requiredData,images : r})
  }catch(err){
    console.log('error while fetching links',err)
    res.json({message:err})
  }
})
app.get('/GETPRODUCTS/:id',async(req,res)=>{
  try{
    const { id } = req.params;

const Fetch = await db.collection(PRODUCTS_COLLECTION).find({Categorie: id}).toArray();
if(Fetch){
res.json({message : Fetch});
}else{
  res.json({message : null});
}
  }catch(err){
    console.log(err);
    res.json({message:err});
  }
})
app.get("/orders", async (req, res) => {
    try {
      const orders = await db.collection(ORDERS_COLLECTION).find({}).toArray();
      res.status(200).json(orders);
    } catch (error) {
      console.error("Error fetching orders:", error);
      res.status(500).json({ error: "Failed to fetch orders." });
    }
  });
  app.get("/ordersToday", async (req, res) => {
    try {
      const today = new Date();
      const formattedToday = today
        .toLocaleDateString("en-GB") // Format as DD/MM/YYYY
        .replace(/\//g, "/"); // Ensure consistency in format
  
      const orders = await db.collection(ORDERS_COLLECTION)
        .find({ date: { $regex: `^${formattedToday}` } }) // Matches orders starting with today's date
        .toArray();
  
      res.status(200).json(orders);
    } catch (error) {
      console.error("Error fetching today's orders:", error);
      res.status(500).json({ error: "Failed to fetch orders." });
    }
  });
  

  app.get('/GETMSGS/:id', async (req, res) => {
    try {
      const { id } = req.params;
      console.log('Received request for messages with ID:', id);
      const messages = await db.collection(MessagesCollection).findOne({ id: id });

  
      res.json(messages.messages); 
    } catch (err) {
      console.error('Error fetching messages:', err);
      res.status(500).json({ message: 'Server error while fetching messages' });
    }
  });
  app.get('/thisCus/:id',async(req,res)=>{
    try{
      const id = req.params.id
const cos = await db.collection(USERS_COLLECTION).findOne({_id:new ObjectId(id)});
const Sales_Orders = await GetThisSalesbyU(id,cos.purchases);
res.json({message : cos,sales : Sales_Orders})
    }catch(err){
      console.log(err)
      res.json({message : {}})
    }
  })

app.get("/messages/:id", async (req, res) => {
  const { id } = req.params;

  try {

    const messages = await db.collection(MessagesCollection).findOne({ id: id }) // Fetch messages sorted by time
if(messages){
  res.json(messages.messages || []);
}else{
  res.json([])
}
   
  } catch (err) {
    console.error("Error fetching messages:", err);
    res.status(500).send("Error fetching messages");
  }
});
app.get('/getproduct101/:id',async(req,res)=>{
    try{
        
const p = await db.collection(PRODUCTS_COLLECTION).findOne({_id : new ObjectId(req.params.id)});

return p ? res.json(p) : res.json({});
    }catch(err){
        console.log(err);
        res.json({message :err});
    }
})
app.get('/getproductRv101/:id',async(req,res)=>{
  try{
      const Target = req.params.id;
      const p = await db.collection(Reviews_Collection).find().toArray();
     const s =  p.filter((item)=>item.data.id == Target && item.status == "confirmed" )
     res.json(s.reverse())
  }catch(err){
      console.log(err);
      res.json({message :err});
  }
})
app.get('/ProductsPl2', async (req, res) => {
  const ITEMS_PER_PAGE = 100;
  try {
    const page = parseInt(req.query.page) || 1; // Default to page 1 if not provided
    const limit = parseInt(req.query.limit) || ITEMS_PER_PAGE; // Default to 10 items per page
    const skip = (page - 1) * limit;

    // Fetch data with pagination
    const data = await db.collection(PRODUCTS_COLLECTION)
      .find()
      .skip(skip)
      .limit(limit)
      .toArray();

    // Get the total number of products for pagination calculation
    const totalProducts = await db.collection(PRODUCTS_COLLECTION).countDocuments();

    res.json({
      data,
      totalProducts,
      currentPage: page,
      totalPages: Math.ceil(totalProducts / limit),
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.get('/names',async(req,res)=>{
  try{
const L = await db.collection(PRODUCTS_COLLECTION).find().toArray()
const N = L.map((item)=>{return {name : item.name , id : item._id , mainImg : item.mainImage}})
res.json( {message : N})    
  }catch(err){
    console.log('error fetching names', err)
    res.json({error : err , message :  []})
  }
})

app.get('/ProductsPl2014', async (req, res) => {
  const ITEMS_PER_PAGE = 100;
  try {
const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || ITEMS_PER_PAGE;
    let searchTerm = req.query.id?.trim() || "";
    if (searchTerm.toLowerCase() === 'cheveux') {
      searchTerm = "cheveu";
    }
   if (searchTerm.toLowerCase() === 'Solaires') {
      searchTerm = "solaire";
    }

    // Build MongoDB filter
  const filter = searchTerm ? {
      $or: [
        { Categorie: { $regex: searchTerm, $options: 'i' } },
        { sous: { $regex: searchTerm, $options: 'i' } },
        { marques: { $regex: searchTerm, $options: 'i' } },
        { name: { $regex: searchTerm, $options: 'i' } }
      ]
    } : {};


    const skip = (page - 1) * limit;

    // Fetch filtered data
    const data = await db.collection(PRODUCTS_COLLECTION)
      .find(filter)
      .skip(skip)
      .limit(limit)
      .toArray();

    // Get total filtered documents
    const totalFiltered = await db.collection(PRODUCTS_COLLECTION)
      .countDocuments(filter);

    res.json({
      data,
      totalProducts: totalFiltered,
      currentPage: page,
      totalPages: Math.ceil(totalFiltered / limit),
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});
app.get('/getblog/:id',async(req,res)=>{
  try{
const all = await db.collection(BLOGS_COLLECTION).find().toArray();
    const result = await db.collection(BLOGS_COLLECTION).findOne({_id:new ObjectId(req.params.id)})
const tags = result.tags;
let p = [];

const T = await Fil(tags,all,req.params.id);

res.json({message : result, sugg: T})
  }catch(err){
    res.json({message : err});
  }
})
app.get('/Blogs', async (req, res) => {
  const ITEMS_PER_PAGE = 15;
  try {
    const page = parseInt(req.query.page) || 1; // Default to page 1 if not provided
    const limit = parseInt(req.query.limit) || ITEMS_PER_PAGE; // Default to 10 items per page
    const skip = (page - 1) * limit;

    // Fetch data with pagination
    const data = await db.collection(BLOGS_COLLECTION)
      .find()
      .skip(skip)
      .limit(limit)
      .toArray();

    // Get the total number of products for pagination calculation
    const totalProducts = await db.collection(BLOGS_COLLECTION).countDocuments();

    res.json({
      data,
      totalProducts,
      currentPage: page,
      totalPages: Math.ceil(totalProducts / limit),
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.get('/repportsgx',async(req,res)=>{
  try{
const r = await db.collection(REPPORTS).find().toArray();
res.json({r});
  }catch(err){
    console.log(err);
    res.json({message:err});
  }
})
app.get('/ProductsPl',async(req,res)=>{
  try{
const Data = await getProductsCache();;
res.json(Data);
  }catch(err){
      console.log(err);
  }
})
app.get("/meBoss",async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "No token provided" });
const DD = await db.collection(ADMIN_COLLECTION).findOne({role : "admin" });
  jwt.verify(token, ACCESS_SECRET, (err, user) => {
      if (err) return res.status(403).json({ error: "Invalid token" });
      res.json({ user : DD, role: user.role });
  });
});
// Secure route to get authenticated user data
app.get("/me", authenticateToken, async (req, res) => {
    try {
        const user = await db.collection(USERS_COLLECTION).findOne(
            { _id: new ObjectId(req.userId) },
            { projection: { password: 0 } }
        );
        if (!user) return res.status(404).json({ error: "User not found" });

        res.json(user);
    } catch (error) {
        res.status(500).json({ error: "Internal Server Error" });
    }
});
app.get('/GetClients',async(req,res)=>{
    try{
     
const Fetch = await getClientsCash();

 return res.json({message : Fetch});
    }catch(err){
        console.log('error getting clients from DB : ',err);
        res.json({message : err});
    }
})
app.get('/GetClientsm101',async(req,res)=>{
  try{
const clients = await fetchUsers404();
res.json({message : clients})
  }catch(err){
    console.log(err)
    res.json({message : []});
  }
})
app.get('/gghotDeals',async(req,res)=>{
  try{
const R = await db.collection(PRODUCTS_COLLECTION).find().toArray();
const F = R.filter((item)=>item.hotDeals === true);
res.json(F);
  }catch(err){
    res.json([err]);
  }
})
app.get('/makepData',async(req,res)=>{
  try{
    const allProducts = await Getmakeups();
    console.log(allProducts)
    res.json({message :allProducts});
  }catch(err){
    res.json({message : err});
  }
})

app.get('/appData',async(req,res)=>{
    try{
const Data = await db.collection(APPCOLLECTION).findOne({pub : "publicatoions"});
const HeroData =await db.collection(APPCOLLECTION).findOne({hero : "HeroS"});
const Send = {
    pub: Data ,
    HeroData : HeroData
}

res.json({Send});
    }catch(err){
        console.log(err);
        res.json({message : err});
    }
})
app.get('/Getnotifications', async(req,res)=>{
    try{
const Task = await db.collection(NOTIFICATIONS_COLLECTION).find().toArray();

res.json(Task);
    }catch(err){
        res.json({message: err});
    }
})
app.get("/GETCards", async (req, res) => {
  try {
    // Fetch data from the respective collections
    const orders = await db.collection(ORDERS_COLLECTION).find().toArray();
    const clients = await db.collection(USERS_COLLECTION).find().toArray();
    const sales = await db.collection(SALES_COLLECTION).find().toArray();
const Costs = await CalculateExpensess();
    const purch = await db.collection(SALES_COLLECTION).find().toArray();

    const Sending = await ReturnData(purch);
    const deliveredItems = Sending.filter((item) => item.status === "Dilivired");

    const Revenu = await CalculateRevenu(deliveredItems);


    res.json({
      message: {
        sales: sales.length,  // Fixed typo here
        orders: orders.length,  // Fixed typo here
        clients: clients.length, 
        Revenu : Revenu,
        cost : Costs
    
      }
    });

  } catch (err) {
    console.log(err);
    res.json({ message: null });
  }
});
app.get('/Getsales',async(req,res)=>{
  try{
   
const purch = await db.collection(SALES_COLLECTION).find().toArray();

const Sending = await ReturnData(purch);

res.json(Sending);
  }catch(err){
    res.json({message:err});
  }
})
app.get("/getInvoices",async(req,res)=>{
  try{
const result = await db.collection(RECIP_COLLECTION).find().toArray();
if(result){
  res.json(result)
}else{
  res.json({message :  []})
}
  }catch(err){
    console.log(err)
    res.json({message : err})
  }
})
app.get('/ggAbout',async(req,res)=>{
  try{
const pp = await db.collection(APPCOLLECTION).findOne({id :'About'})
if(pp){
  res.json({message : pp.content})
}else {
  res.json({message : ''})
}

  }catch(err){
    console.log(err)
    res.json({message : err});
  }
})
app.get('/getRev',async(req,res)=>{
  try{
const Re = await db.collection(Reviews_Collection).find().toArray();
res.json({Re})
  }catch(err){
    console.log(err);
  }
})
app.get('/getPostWithid/:id',async(req,res)=>{
  try{
const ID = req.params.id;
const item  = await db.collection(BLOGS_COLLECTION).findOne({_id : new ObjectId(ID)});
res.json({message : item})
  }catch(err){
    console.log(err)
    res.json({message : {}})
  }
})
app.get('/AnimPR',async(req,res)=>{
  try{
const result = await getSpecifyProducts('animals');
res.json({message : result})
  }catch(err){
    console.log(err)
    res.json({message : [] , err : []})
  }
})
// Refresh Token Route
app.post('/invoices',async(req,res)=>{
  try{
    console.log('iv ;' ,req.body)
const result = await db.collection(RECIP_COLLECTION).insertOne(req.body);
res.json({message : true})
  }catch(err){
    res.json({message : err});
  }
})
app.post("/refresh", (req, res) => {
  const refreshToken = req.cookies.refreshToken;


  if (!refreshToken) {

      return res.status(401).json({ error: "No refresh token provided" });
  }

  jwt.verify(refreshToken, REFRESH_SECRET, (err, user) => {
      if (err) {
          return res.status(403).json({ error: "Invalid refresh token" });
      }

      const newAccessToken = jwt.sign({ id: user.id, role: user.role }, ACCESS_SECRET, { expiresIn: "15m" });
      res.json({ accessToken: newAccessToken });
  });
});
app.post("/refreshAD101", async (req, res) => {
  const refreshToken = req.cookies.refreshToken1;

  console.log("Refresh token from cookie:", refreshToken);
  
  if (!refreshToken) {
    return res.status(401).json({ error: "No refresh token provided" });
  }

  try {
    // Verify the refresh token
    const decoded = jwt.verify(refreshToken, REFRESH_SECRET);

    // Find the session-based refresh token in Redis
    const storedToken = await redis_client.get(`refresh:${decoded.id}:${decoded.sessionId}`);

    if (!storedToken || refreshToken !== storedToken) {
      return res.status(403).json({ error: "Invalid or expired refresh token" });
    }

    // Generate new access token
    const newAccessToken = jwt.sign({ id: decoded.id, role: decoded.role }, ACCESS_SECRET, { expiresIn: "15m" });

    console.log("✅ Refresh token valid, new access token issued");

    res.json({ accessToken: newAccessToken });
  } catch (err) {
    console.error("❌ Refresh token verification failed:", err);
    res.status(403).json({ error: "Invalid refresh token" });
  }
});
app.post('/updateReviewDel/:id',async(req,res)=>{
  try{
  
    const id = req.params.id;
    const review = await db.collection(Reviews_Collection).deleteOne({ _id: new ObjectId(id)});
    res.json({message :'done'})
  }catch(err){
    console.log(err)
    res.json({message:err})
  }
})
app.post('/saveDeals',async(req,res)=>{
  try{
console.log(req.body);
const Data = req.body;
Data.forEach(async (pr)=>{
  const ypd = await db.collection(PRODUCTS_COLLECTION).updateMany({_id : new ObjectId(pr.productId)}, { $set: {
    hotDeals : true,
    expiration : pr.expiration
           }})
           
})
  res.json({message : true})
  }catch(err){
    console.log(err);
    res.json({err});
  }
})
app.post('/updateReviewStatus/:id',async(req,res)=>{
  try{
const status = req.body.status;
const id = req.params.id;
const review = await db.collection(Reviews_Collection).updateOne({ _id: new ObjectId(id)
  }, {
    $set: {
      status: status
      }
      }
      );

      res.json({message : true})


  }catch(err){
    console.log(err)
    res.json({message : err})
  }
})
app.post('/About',async(req,res)=>{
  try{
    const target = await db.collection(APPCOLLECTION).findOne({id : "About"})
    if(target){
      const d = await db.collection(APPCOLLECTION).updateOne({id : 'About'},{$set :{content: req.body}});
      res.json({message : true})
    }else{
      const d = await db.collection(APPCOLLECTION).insertOne({id : 'About',content : req.body})
      res.json({message : true})
    }

  }catch(err){
    console.log(err);
res.json({message : err})
  }
})
app.post('/repportsgxReplay/:id',async(req,res)=>{
  try{
    const target = req.params.id;
    const message = req.body;
    const GTA = await db.collection(REPPORTS).findOne({_id: new ObjectId(target)});
    if(GTA){
      const newMessage = await db.collection(REPPORTS).updateOne({_id: new ObjectId
        (target)},{$push:{Replay:{reply :message.reply,replyDate : message.replyDate }}});
ReplayToContact({name: GTA.name,email:GTA.email,message : newMessage.reply})
    }

res.json({message :true})
  }catch(err){
    console.log('err',err);
    res.json({message:false});
  }
})
app.post('/SubSr',async(req,res)=>{
  try{

   const insertGdj = await db.collection(process.env.SUB_COLLECTION).findOne({email : req.body.email})
   if(insertGdj){
res.json({message : 'déjà inscrits!'});
   }else{
await db.collection(process.env.SUB_COLLECTION).insertOne({email : req.body.email , sub: true , name : req.body.name})
res.json({message : 'abonné avec succès !'});
   }  
  
  }catch(err){
    console.log(err)
    res.json({message : 'err'})
  }
})
app.post('/delPostk',async(req,res)=>{
  try{
    await db.collection(BLOGS_COLLECTION).deleteOne({_id : new ObjectId(req.body.id)})
    res.json({message : true})
  }catch(err){
    res.json({message : err})
  }
})
app.post('/postlinks',async(req,res)=>{
  try{
    const data = req.body
const r = await db.collection(LINK_COLLECTION).insertOne({content :data});
res.json({message : true})
  }catch(err){
    console.log(err)
    res.json({message : false})
  }
})
app.post('/findme/:email',async(req,res)=>{
  try{
    const user = await db.collection(USERS_COLLECTION).findOne({email : req.params.email});
    const verificationToken = uuid.v4();
    const verificationCode = Math.floor(10000 + Math.random() * 90000).toString();

    if(user){
      await SendVerifCode(req.params.email,user.full_name,verificationCode,verificationToken);
      await db.collection(USERS_COLLECTION).updateMany({email:user.email},{$set:{token : verificationToken, code : verificationCode}})
   const k =   await redis_client.set(verificationToken, user.email, { EX: 900 });
   console.log(k)
      res.json({message : true, token : verificationToken})
    
    }else{
      res.json({message : false});
    }
  }catch(err){
    console.log(err)
    res.json({message : err});
  }
})
app.post('/VerifyAccount', async (req, res) => {
    try {
        const { token, fullCode } = req.body;

        // Check if user exists
        const user = await GET_USER_BY_Token(token);
        if (!user) {
            return res.json({ message: 'expired' });
        }

        // Check if the code matches
        if (user.code !== fullCode) {
            return res.json({ message: false });
        }

        // Update user status
        const result = await db.collection(USERS_COLLECTION).updateMany(
            {token: token }, // Filter user by token
            {
                $set: {
                    active: true,
                    token: '',
                    code: '',
                },
            }
        );

        // Check if the update was successful
        return result.modifiedCount > 0
            ? res.json({ message: true ,skls : {type : "new user", message : `${user.name}  verified his account ` ,  date : formatDate101(new Date())}})
            : res.json({ message: false });

    } catch (err) {
        console.error('Error verifying email:', err);
        res.status(500).json({ message: 'Internal server error' });
    }
});
app.post('/vme/:id',async(req,res)=>{
  try{
    const id = req.params.id
const u = await db.collection(USERS_COLLECTION).findOne({token:id})

if(u){
const code = req.body.code
if(code == u.code){
await db.collection(USERS_COLLECTION).updateMany({token:id},{$set :{token :"",code:''}})
await redis_client.del(id);
  res.json({message:true,id : u._id})
}
}else{
  res.json({message:false});
}
  }catch(err){
    console.log(err)
      res.json({message: err});
    
  }
})
app.post('/sayee/:id',async(req,res)=>{
  try{
    const id =req.params.id
const user = await db.collection(USERS_COLLECTION).findOne({_id: new ObjectId(id)});

if(user){
  
const code = req.body.pass;

const hashedPassword = await hashPassword(code);
const r = await db.collection(USERS_COLLECTION).updateOne({_id : new ObjectId(id)}, {$set:{ password : hashedPassword}})

r.modifiedCount > 0 ? res.json({message : true}) : res.json({message : false})
}else{
  res.json({message : false});
}
  }catch(err){
    console.log(err)
    res.json({message:err})
  }
})

app.get('/estque/:id',async(req,res)=>{
  try{
    const id = req.params.id;
    const email = await redis_client.get(id);
  
    if(email){
      res.json({message :true})
    }else{
      res.json({message : false})
    }
  }catch(err){
    console.log(err)
    res.json({message : err})
  }
})
app.post('/ChangeAvatar', async (req, res) => {
    try {
        const data = req.body;
        const collection = db.collection(USERS_COLLECTION);
        const Target = await collection.findOne({ _id: new ObjectId(data.id) });
        if (!Target) return res.json({ message: false });

        // Update profile picture
        const updateResult = await collection.updateOne(
            { _id: new ObjectId(data.id) },
            { $set: { pdf: data.link } }
        );

        if (updateResult.modifiedCount === 1) {
            res.json({ message: true });
        } else {
            res.json({ message: "No changes made" });
        }
    } catch (err) {
        console.error("Error updating avatar:", err);
        res.status(500).json({ error: err.message });
    }
});
app.post('/UpdateAccount', async(req,res)=>{
    try{
      const Fetch = await GET_USER_BY_EMAIL(req.body.email);
   
      if(Fetch){
        const collection = db.collection(USERS_COLLECTION);
        const updateResult = await collection.updateOne(
            { _id: new ObjectId(Fetch._id) },
            { $set: {
                name: req.body.name,
                email: req.body.email,
               adress : req.body.address,
               tel : req.body.phone,
                }}
)
return updateResult.modifiedCount > 0 ? res.json({message : "success"}): res.json({message : 'failed'});
}else{
    res.json({message : "user didn't found in DB"});
}


    }catch(err){
        res.json({err: err});
    }
});

app.post('/ChangePassword',async(req,res)=>{
    try{
        const Fetch = await GET_USER_BY_EMAIL(req.body.email);
        const collection = db.collection(USERS_COLLECTION);
        console.log(req.body);
        if(Fetch){
            const password = req.body.password;
           
const newHashedPass = await hashPassword(req.body.newpassword);
const C = await bcrypt.compare(password, Fetch.password)
if(C){
    const updateResult = await collection.updateOne(
        { _id: new ObjectId(Fetch._id) },
        { $set: {
     password : newHashedPass
            }}
    )
    return updateResult.modifiedCount > 0 ? res.json({message : "success"}): res.json({message : 'failed'});
}else{
res.json({message : "old password is worng"});
}

        }else{
            res.json({message : 'user didnt found in DB'});
        }
    }catch(err){
        console.log('error updating password : ', err);
        res.json({message : err});
    }
})
app.get('/Getproduct/:id', async(req, res) => {
   
try{
    const { id } = req.params;  // Access the 'id' from the URL parameter
  
const product = await db.collection(PRODUCTS_COLLECTION).findOne({_id : new ObjectId(id)});

  return product ? res.json({message : product}) : res.json({message : "product not found !!"});
}catch(err){
res.json({message : err});
}
  
  
    
  });
app.get('/lvs',async(req,res)=>{
  try{
const i =await db.collection(APPCOLLECTION).findOne({id : "setup"});

res.json({message : i})
  }catch(err){
    console.log(err);
    res.json({message : []})
  }
})
app.post('/linksCTI',async(req,res)=>{
  try{
    if(await db.collection(APPCOLLECTION).findOne({id : req.body.categorie})){
      await db.collection(APPCOLLECTION).updateOne({id : req.body.categorie},{$set : {link : req.body.link}})
    }else{
      await db.collection(APPCOLLECTION).insertOne({id : req.body.categorie , link : req.body.link})
    }

res.json({message : true})
    }catch(err){
    console.log(err)
    res.json({message : false})
  }
})

  

app.post("/contact", async(req, res) => {
    console.log("Received contact message:", req.body);
    const newMessage = {
      ...req.body,
      date: formatDate101(new Date()), // Format the current date
    };
    const collection = db.collection(REPPORTS);
    const Do = await collection.insertOne(newMessage);
    
    res.status(200).json({ message: "Message received successfully" });
  });
  app.post('/banUser',async(req,res)=>{
    try{
        const Fetch = await getUserByID(req.body.id);
if(Fetch){
    const collection = db.collection(USERS_COLLECTION);
    const updateResult = await collection.updateOne(
        { _id: new ObjectId(Fetch._id) },
        { $set: {
            isBanned : true
            }}
            )
            await saveClientsCash();
res.json({message : true})
        }else{
            res.json({message : 'user not found !'});
        }

    }catch(err){
        console.log('error ban user : ', err);
        res.json({message : err});
    }
  })
  app.post('/deleteUser',async(req,res)=>{
    try{
        const Fetch = await getUserByID(req.body.id);
        
if(Fetch){
    const collection = db.collection(USERS_COLLECTION);
const deleteResult = await collection.deleteOne(
    { _id: new ObjectId(Fetch._id) }
    )
    await saveClientsCash()
    res.json({message :`User With ID ${Fetch._id} Deleted`});
}else{
    res.json({message : 'User Not Found'});
}
    }catch(err){
        console.log('error ban user : ', err);
        res.json({message : err});
    }
  })
  app.post('/unbanUser',async(req,res)=>{
    try{
        const Fetch = await getUserByID(req.body.id);
        if(Fetch){
            const collection = db.collection(USERS_COLLECTION);
            const updateResult = await collection.updateOne(
                { _id: new ObjectId(Fetch._id) },
                { $set: {
                    isBanned : false
                    }}
                    )
                    await saveClientsCash();
        res.json({message : true})}
    }catch(err){
        console.log('error unbanding user');
        res.json({message: err});
    }
  })
  app.post('/modify_products', async (req, res) => {
    try {

      const filter = { _id: new ObjectId(req.body.id) };
  
      const update = { $set: req.body };
  const Target = await db.collection(PRODUCTS_COLLECTION).findOne(filter);
  if(Target){



    const result = await db.collection(PRODUCTS_COLLECTION).updateMany(filter, update);
  await saveProductsInCache();
    res.json({
      message: 'Products updated successfully',
     
      modifiedCount: result.modifiedCount 
    });

  }

    } catch (err) {
      res.status(500).json({ message: err.message });
    }
  });

  app.post('/upLev',async(req,res)=>{
    try{
  const target = await db.collection(APPCOLLECTION).findOne({id: "setup"});
  if(target){
    const a= await db.collection(APPCOLLECTION).updateOne({id: 'setup'}, {$set :{lv : req.body.lv}})

    res.json({message : true})
  }else{
    await db.collection(APPCOLLECTION).insertOne({id : 'setup', lv : req.body.lv})
    res.json({message : true})
  }

    }catch(err){
      console.log(err);
      res.json({message :  err})
    }
  })
  app.post('/upPnt',async(req,res)=>{
    try{
  
const a= await db.collection(APPCOLLECTION).updateOne({id: 'setup'}, {$set :{merci : req.body.merci}})

res.json({message : true})
    }catch(err){
      console.log(err);
      res.json({message :  err})
    }
  })
  app.post('/upGrt',async(req,res)=>{
    try{
  
const a= await db.collection(APPCOLLECTION).updateOne({id: 'setup'}, {$set :{Gratuit : req.body.Gratuit}})

res.json({message : true})
    }catch(err){
      console.log(err);
      res.json({message :  err})
    }
  })
  app.get('/getuserPurchases/:id', async (req, res) => {
    try {
      const userId = req.params.id;
      
      // Validate ID format
      if (!ObjectId.isValid(userId)) {
        return res.status(400).json({ message: "Invalid user ID format" });
      }
  
      const user = await db.collection(USERS_COLLECTION).findOne({ 
        _id: new ObjectId(userId) 
      });
  
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }
  
      if (!user.purchases || user.purchases.length === 0) {
        return res.json({ message: "No purchases found", purchases: [] });
      }

      // Convert to array of promises
      const purchasePromises = user.purchases.map(async (item) => {
        try {
          const orderId = item.purchases.id; // Verify this matches your schema
          if (!ObjectId.isValid(orderId)) {
            console.warn(`Invalid order ID: ${orderId}`);
            return null;
          }
  
          const order = await db.collection(ORDERS_COLLECTION).findOne({
            _id: new ObjectId(orderId)
          });
  
          return order || null;
        } catch (error) {
          console.error(`Error fetching order ${orderId}:`, error);
          return null;
        }
      });
  
      // Wait for all promises to resolve
      const purchases = await Promise.all(purchasePromises);
      
      // Filter out null values (failed lookups)
      const validPurchases = purchases.filter(p =>  p !== null);
   
  
      res.json({
        message: "Success",
        count: purchases.length,
        purchases: purchases
      });
  
    } catch (err) {
      console.error("Server error:", err);
      res.status(500).json({ 
        message: "Internal server error",
        error: err.message 
      });
    }
  });

  app.post('/Deleteproducts',async(req,res)=>{
    try{
const collection =await db.collection(PRODUCTS_COLLECTION).deleteOne({_id : new ObjectId(req.body.id)});
await saveProductsInCache();
res.json({message : true});
    }catch(err){
        res.json({message : err});
    }
  })
  app.post('/add_products',async(req,res)=>{
    try{

const collection = db.collection(PRODUCTS_COLLECTION);
const collection101 = db.collection(EXPENESS_COLLECTION)
const data = req.body;
data.status = true;
data.reviews = [];
const addResult = await collection.insertOne(data);
await saveProductsInCache();


res.status(201).json({
    message: 'Product added successfully',
    productId: addResult.insertedId,
  });
    }catch(err){
        console.log(err);
    }
  })
  app.post('/publi', async (req, res) => {
    try {
      const collection = db.collection(APPCOLLECTION);
      const { f1, f2 } = req.body;
  
      if (f1 !== undefined && f2 === undefined) {
        const addResult = await collection.updateOne(
          { pub: 'publicatoions' }, // Filter: Find a document where `pub` equals 'publicatoions'
          { $set: { 'Data.0': f1.link } } // Update operation: Set the first index of `Data` to `f1`
        );
      } else if (f1 === undefined && f2 !== undefined) {
        const addResult = await collection.updateOne(
          { pub: 'publicatoions' }, // Filter: Find a document where `pub` equals 'publicatoions'
          { $set: { 'Data.1': f2.link } } // Update operation: Set the second index of `Data` to `f2`
        );
      } else if (f1 !== undefined && f2 !== undefined) {
        const addResult = await collection.updateOne(
          { pub: 'publicatoions' }, // Filter: Find a document where `pub` equals 'publicatoions'
          { $set: { Data: [f1.link, f2.link] } } // Update operation: Set the `Data` array with both `f1` and `f2`
        );
      } else {
        return res.status(400).json({ message: 'Invalid request. Both fields cannot be undefined.' });
      }
  
      res.json({ message: 'Product added successfully' });
    } catch (err) {
      console.log(err);
      res.status(500).json({ message: 'An error occurred while processing the request.' });
    }
  });
  app.post('/hero', async (req, res) => {
    const { images } = req.body;
  
    if (!images || !Array.isArray(images)) {
      return res.status(400).json({ message: 'Invalid request: "images" must be an array.' });
    }
  
    // Update our in-memory store.
    heroImages = images;
  
    try {
      const r = await db.collection(APPCOLLECTION).updateOne(
        { pub: "publicatoions" },
        { $set: { Hero: heroImages } }
      );
      console.log('Updated hero images:', heroImages);
      res.status(200).json({ message: 'Hero images updated successfully.', images: heroImages });
    } catch (err) {
      console.error('Error updating hero images in DB:', err);
      res.status(500).json({ message: 'Error updating hero images in DB' });
    }
  });
  app.post('/update_personnel', async(req,res)=>{
try{
  console.log(req.body)
  const K = await db.collection(ADMIN_COLLECTION).findOne({_id : new ObjectId(req.body.id)})
 
  const Do = await db.collection(ADMIN_COLLECTION).updateMany(
    { _id: new ObjectId(req.body.id) }, // Filter
    { $set: { prf: req.body.prf, name: req.body.name } } // Update operation
  );
  return Do.modifiedCount > 0 ? res.json({message : true}) : res.json({message : false})
}catch(err){
  res.json({message : err})
}
  })
  app.post('/setNewLink',async(req,res)=>{
    try{
const result = await db.collection(LINK_COLLECTION).insertOne({name :req.body.Categorie ,content : req.body});
res.json({message : true});
    }catch(err){
      console.log(err);
      res.json({message:err});
    }
    })
    app.post('/request_command/:id', async (req, res) => {
      try {
        const data = req.body;
        data.status = "pending"; 
        data.methode = 'on delivery'
        if(req.params.id){
          data.auth = req.params.id
          if(data.iu){
     
         await db.collection(USERS_COLLECTION).updateOne({_id : new ObjectId(req.params.id)}, {$inc: { "pts.used": data.utiliste }})
          }
        }else{
          data.auth = null
        }

        data.date = new Intl.DateTimeFormat('en-GB', { 
          day: '2-digit', 
          month: '2-digit', 
          year: 'numeric', 
          hour: '2-digit', 
          minute: '2-digit', 
          hour12: false 
        }).format(new Date());
    
        // Insert into database
        
        const result = await db.collection(ORDERS_COLLECTION).insertOne(data);
    data._id = result.insertedId
        res.json({ message: "Request saved successfully",
           notifu: {
          type : "order",
          _id : result.insertedId,
          date : data.date,
          message : "New order Request"
        }, tbl :data
      
      });
      } catch (err) {
        console.log(err);
        res.status(500).json({ message: "Server error", error: err });
      }
    });

  app.post('/updatePost1024/:id',async(req,res)=>{
    try{
      const id = req.params.id
      const up = req.body

      const result = await db.collection(BLOGS_COLLECTION).updateMany({ _id: new ObjectId(id
        ) }, { $set: {  title : up.title , content : up.content , image : up.image , description : up.description, tags : up.tags } });
console.log(result.modifiedCount)
res.json({success : true})
    }catch(err){
      console.log(err)
      res.json({success : false})
    }
  })

app.post('/ADchangePassword', authenticateToken, async (req, res) => {
    const { oldPassword, newPassword } = req.body;
  

    try {
      
        const admin = await db.collection(ADMIN_COLLECTION).findOne({ _id: new ObjectId(req.userId) });
        
        if (!admin) {
            return res.status(404).json({ error: "Admin not found" });
        }

  
        const isOldPasswordValid = await bcrypt.compare(oldPassword, admin.password);
        if (!isOldPasswordValid) {
            return res.status(400).json({ error: "Old password is incorrect" });
        }

     
        const hashedNewPassword = await hashPassword(newPassword);

        const updateResult = await db.collection(ADMIN_COLLECTION).updateOne(
            { _id: new ObjectId(req.userId) },
            { $set: { password: hashedNewPassword } }
        );

        if (updateResult.modifiedCount > 0) {
            return res.json({ message: "Password changed successfully" , success :true});
        } else {
            return res.status(500).json({ error: "Failed to update password" });
        }
    } catch (err) {
        console.error("Error changing password:", err);
        res.status(500).json({ error: "Internal Server Error" });
    }
});

app.post('/ADchangePasswordPin101', authenticateToken, async (req, res) => {
  const { CodeP, newCodeP } = req.body;


  try {
    
      const admin = await db.collection(ADMIN_COLLECTION).findOne({ _id: new ObjectId(req.userId) });
      
      if (!admin) {
          return res.status(404).json({ error: "Admin not found" });
      }


      const isOldPasswordValid = await bcrypt.compare(CodeP, admin.pinCodeHash);
      if (!isOldPasswordValid) {
          return res.status(400).json({ error: "Old code is incorrect" });
      }

   
      const hashedNewPassword = await hashPassword(newCodeP);

      const updateResult = await db.collection(ADMIN_COLLECTION).updateOne(
          { _id: new ObjectId(req.userId) },
          { $set: { pinCodeHash: hashedNewPassword } }
      );

      if (updateResult.modifiedCount > 0) {
          return res.json({ message: "Code changed successfully" , success :true});
      } else {
          return res.status(200).json({ error: "Failed to update code ! refresh & try again " });
      }
  } catch (err) {
      console.error("Error changing password:", err);
      res.status(200).json({ error: "Internal Server Error" });
  }
});


app.post('/removeFromFav',async(req,res)=>{
  try{

const user = await db.collection(USERS_COLLECTION).findOne({_id : new ObjectId(req.body.uid)})
if(user){
 
  const fav = user.Fav

  const index = fav.filter((o)=>{

return    o._id == req.body.id})
  

  if(index.length > 0){
    const i = fav.indexOf(index[0]);
    fav.splice(i,1)
    const updateResult = await db.collection(USERS_COLLECTION).updateOne(
      { _id: new ObjectId(req.body.uid) },
      { $set: { Fav: fav } }
      );
      if (updateResult.modifiedCount > 0) {
        return res.json({ message: true });
        } else {
          return res.status.json({ message: false });
          }
          }
}
  }catch(err){
    console.log(err);
    res.json({message : false})
  }
})

app.post('/update_orders_status/:id',async(req,res)=>{
    try{
const id = req.params.id
if(id){
  const Target = await db.collection(ORDERS_COLLECTION).findOne({_id :new ObjectId(id)});

    const collection = await db.collection(ORDERS_COLLECTION).updateOne({ _id: new ObjectId(id) },{$set:{status: req.body.status}}, {returnOriginal: false});
if(req.body.status === "confirmed" ){
  
  const newSale = await db.collection(SALES_COLLECTION).insertOne({purchases : {
    id : id,
    status : 'DeliveryPending',
  }})   
  
  const updateUser = await UpdateUSER_SALES(id ,Target.req_email,{u:Target.utiliste ,i: Target.iu});
  
const n = JSON.parse(Target.items);
const Y = [];
let Total = 0;

n.forEach(async (p)=>{
  const DW = await db.collection(PRODUCTS_COLLECTION).findOne({_id : new ObjectId(p.id)})
 
  const Ndata = {

service : p.name,rate: p.current_price, description :DW.description,qty : p.quantity,
  }
  Total+= p.quantity * p.current_price;
  
Y.push(Ndata);
})
const l = await db.collection(RECIP_COLLECTION).find().toArray()

  const Gratui =await db.collection(APPCOLLECTION).findOne({id : "setup"});
  const Gratuit = Gratui.Gratuit;
  let nls = 0;
if(Target.iu){
nls = Target.utiliste * Target.merci;

}

  const Invoke = {
    status : "pending",
    invoiceNo : l.length ? l.length + 1 : 1 ,
    invoicedTo : [Target.name_req, Target.address,Target.tel ],
    payTo : ['AllParamarmacie', "AllParapharmcie.com"],
  items :Y,
  date : Target.date,
  subTotal : Total,
  Discount  : nls,
tax : 7,
total : Total + 7,
Gratuit : Gratuit,

  }
console.log("LAalalala :", Invoke)
 const AL =  await db.collection(RECIP_COLLECTION).insertOne(Invoke);
  
 



}else{
  const T = await db.collection(SALES_COLLECTION).findOne({'purchases.id': id })
  if(T){
    await db.collection(SALES_COLLECTION).deleteOne({'purchases.id' : id})
  }
}

res.status(200).json({ message: "Sattus updated Succesfully !" })             
}else{
    res.json({message : "No id given !!"});
}
    }catch(err){
        res.json({message: err});
    }
})

 

  app.post('/addReview/:id', async (req, res) => {
    try {
      const productId = req.params.id;
      const review = req.body; // The review data sent from the frontend, including status and date
      review.status = review.status || false; // Ensure status is set to false if not provided
      review.date = review.date || new Date().toISOString(); // If no date is provided, use the current date
  
      // Find the product in the database
      const product = await db.collection(PRODUCTS_COLLECTION).findOne({ _id: new ObjectId(productId) });
  
      if (product) {
        // Add the review to the product's reviews array
        await db.collection(PRODUCTS_COLLECTION).updateOne(
          { _id: new ObjectId(productId) },
          { $push: { reviews: review } } // Push new review into the reviews array
        );
        res.status(200).send({ message: "Review added successfully!" });
      } else {
        res.status(404).send({ message: "Product not found" });
      }
    } catch (err) {
      console.error(err);
      res.status(500).send({ message: "Internal Server Error" });
    }
  });
  
  

app.post("/logout", (req, res) => {
    res.clearCookie("refreshToken");
    res.json({ message: "Logged out" });
  });
app.post("/logoutAD",async (req, res) => {
  const refreshToken = req.cookies.refreshToken1;

  if (!refreshToken) {
    return res.status(400).json({ error: "No refresh token found" });
  }

  try {
    const decoded = jwt.verify(refreshToken, REFRESH_SECRET);
    await redis_client.del(`refresh:${decoded.id}:${decoded.sessionId}`); // Remove only this session's token

    res.clearCookie("refreshToken1");

    console.log(`✅ Admin logged out. Session ID: ${decoded.sessionId}`);

    res.json({ message: "Logout successful" });
  } catch (error) {
    console.error("❌ Logout error:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});


app.post("/updateInvokestatus", async (req, res) => {
  try {
  
    const { invoiceNo, status } = req.body;

    const updatedReceipt = await db.collection(RECIP_COLLECTION).findOneAndUpdate(
      { invoiceNo: invoiceNo }, 
      { $set: { status: status } }, 
    
    );

  

    res.json({ message: "Status updated"});
  } catch (error) {
    console.error("Error updating status:", error);
    res.status(500).json({ message: "Internal Server Error" });
  }
});
app.post("/delete-receipt", async (req, res) => {
  try {
  
    const { invoiceNo } = req.body;

    const deletedReceipt = await db.collection(RECIP_COLLECTION).findOneAndDelete({ invoiceNo });



    res.json({ message: "Status updated"});
  } catch (error) {
    console.error("Error updating status:", error);
    res.status(500).json({ message: "Internal Server Error" });
  }
});
app.get('/brands',async(req,res)=>{
  try{
const B = await db.collection(BRANDS).find().toArray();
res.json({message:B})


}catch(err){
    console.log(err)
    res.json({message :[]})
  }
})
app.post('/add_brand',async(req,res)=>{
  try{
await db.collection(BRANDS).insertOne(req.body)
res.json({message:true})
  }catch(err){
    console.log(err)
    res.json({message : err})
  }
})

app.post('/postlinks1/:id',async(req,res)=>{
  try{
    const uid = req.params.id
const data = req.body;
    const Target = await db.collection(LINK_COLLECTION).findOne({_id : new ObjectId(uid)});
if(Target){
  await db.collection(LINK_COLLECTION).updateMany({_id : new ObjectId(uid)}, {$set :{
    'content.linkName' : data.linkName ,
    'content.categorie': data.categorie,
    "content.slug" :data.slug,
    "content.products" : data.products,
    
    }})
    res.json( {message : true})
}else{
  res.json({message : false})
}
  }catch(err){
    console.log(err)
    res.json({message : err})
  }
})
app.post('/deleteLinkf/:id',async(req,res)=>{
  try{
    const uid = req.params.id
 
        const Target = await db.collection(LINK_COLLECTION).findOne({_id : new ObjectId(uid)});
        if(Target){
          await db.collection(LINK_COLLECTION).deleteOne({_id : new ObjectId(uid)})
          res.json( {message : true})
        }
        else{
          res.json({message : false})
        }
  }catch(err){
  console.log(err)
    console.log(err)
    res.json({message : err})
  }
})

// Socket.io 

io.on("connection", (socket) => {
   
    
  socket.on('send-message',async(data)=>{
    const date = formatDate101(new Date())
    data.date = date;
    const saved = await SaveMSg(data);
   socket.broadcast.emit('recive-admin-msg',data);
  })

  app.post('/saveBlog', async(req,res)=>{
    try{
      const se = req.body.Data;
      const date = formatDate101(new Date());
      se.date = date
const result = await db.collection(BLOGS_COLLECTION).insertOne(se);

result.acknowledged ? async()=>{
  socket.broadcast.emit('newBlog', req.body.Data);
  const sub = await db.collection(USERS_COLLECTION).find({sub : true}).toArray()
  const L = await db.collection(process.env.SUB_COLLECTION).find().toArray()
sub.forEach((client)=>{
  SendAbonnement({mail : client.email , name : client.name , message : `new post link ` , link : `blog_item?id=${result.insertedId}`})
})
L.forEach((client)=>{
  SendAbonnement({mail : client.email , name : client.name , message : `new post link ` , link : `blog_item?id=${result.insertedId}`})
})

} : null
return result.acknowledged ? res.json({message : true}) : res.json({message : false});
    }catch(err){
      console.log(err);
      res.json({message : err});
    }
  })

 socket.on('send-messageQuest',async(data)=>{
console.log(data)
 })
socket.on('Newoder',async(data)=>{
 const SaveNotification = await SaveNotificationFct(data);

 socket.broadcast.emit('ORDER', data);


})
socket.on('tbl', (data)=>{
  socket.broadcast.emit('tbf', data)
})
socket.on("send-admin-msg",async (data) => {
  const date = formatDate101(new Date())
  data.date = date   
    const saved = await SaveAdMSg(data);
 
    // Emit message to all clients (or use specific target)
    socket.broadcast.emit("receive-from-admin-msg", data);
  });
  socket.on('send-report',async(data)=>{
   await db.collection(NOTIFICATIONS_COLLECTION).insertOne({
    type : "Repport",
    date:formatDate101(new Date()),
    message : `${data.name} send you a messgae , will be saved in the repports ..`
   })
    socket.broadcast.emit('recive-report',{
      type : "Repport",
      date:formatDate101(new Date()),
      message : `${data.name} just Send you a message ..`
     });
  })
  socket.on('send-review',async(data)=>{
    try{

const Note = await db.collection(NOTIFICATIONS_COLLECTION).insertOne({type : 'review', date:formatDate101(new Date()),
  message : `${data.username} made a rivew on  ..` })
  const Review = await db.collection(Reviews_Collection).insertOne({data: data, date:formatDate101(new Date())});
  socket.broadcast.emit('recive-review',{
    type : "review",
    date:formatDate101(new Date()),
    message : `${data.username} just Send you a message ..`
   });
   socket.broadcast.emit('newReview',{data: data, date:formatDate101(new Date())})
    }catch(err){
      console.log(err);
    }
  })

  socket.on('verified-new', async(data)=>{
    try{
const saving = await db.collection(NOTIFICATIONS_COLLECTION).insertOne(data);
await saveClientsCash();
socket.broadcast.emit('new-user', data)
    }catch(err){
      console.log(err);
    }
  })
    // Handle disconnections (when users leave the app)
    socket.on("disconnect", async () => {
      console.log(`User ${socket.id} disconnected`);
  
      // Remove the user from the available list when they disconnect
   
    });
  });

// Start server
server.listen(port, () => {
    console.log(`Server running on port ${port}`);
  });
