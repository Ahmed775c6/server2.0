const { createClient } = require('redis');
const { MongoClient, ObjectId } = require('mongodb');
require('dotenv').config();
const compression = require('compression');

// Database configuration
const dbName = process.env.DBNAME;
const uri  = process.env.MONGO_URI;
const USERS_COLLECTION = process.env.USERS_COLLECTION; // Ensure this is in your .env
const client = new MongoClient(uri);
let db = client.db(dbName);

// Redis client setup
const redisClient = createClient({
  url: process.env.REDIS_URL101 // Add to .env if needed
});

redisClient.on('error', (err) => console.log('Redis Client Error', err));

// Connect to databases
async function connectDB() {
    try {
        await client.connect();
        db = client.db(dbName);

        console.log("Connected to MongoDB");
    } catch (err) {
        console.error("Error connecting to MongoDB:", err);
        process.exit(1);
    }
}

async function connectRedis() {
    try {
        await redisClient.connect();
        console.log("Connected to Redis");
    
    } catch (err) {
        console.error("Error connecting to Redis:", err);
        process.exit(1);
    }
}

// Initialize connections
(async () => {
    await connectDB();
    await connectRedis();
})();

const PRODUCTS_COLLECTION = process.env.PRODUCTS_COLLECTION;

// Cache products in Redis
const saveProductsInCache = async () => {
    try {
        const collection = db.collection(PRODUCTS_COLLECTION);
        const result = await collection.find().toArray();
        await redisClient.set('products', JSON.stringify(result));
        return true;
    } catch (err) {
        console.log('Error saving products to cache:', err);
        return false;
    }
}
const saveClientsCash = async () => {
    try {
        const collection = db.collection(USERS_COLLECTION);
        const result = await collection.find().toArray();
        await redisClient.set('clients', JSON.stringify(result));
        return true;
    } catch (err) {
        console.log('Error saving products to cache:', err);
        return false;
    }
}


// Get products from cache or database
const getProductsCache = async () => {
    try {
        const cachedProducts = await redisClient.get('products');
        
        if (cachedProducts) {
        
            return JSON.parse(cachedProducts);
        } else {
        
            // Fetch from database
            const collection = db.collection(PRODUCTS_COLLECTION);
            const products = await collection.find().toArray();
            // Update cache
            await redisClient.set('products', JSON.stringify(products));
            return products;
        }
    } catch (err) {
        console.log('Error in cache access:', err);
        throw err; // Rethrow to handle in calling function
    }
}
const getClientsCash = async()=>{
       try {
        const cachedProducts = await redisClient.get('clients');
        
        if (cachedProducts) {
        
            return JSON.parse(cachedProducts);
        } else {
        
            // Fetch from database
            const collection = db.collection(USERS_COLLECTION);
            const products = await collection.find().toArray();
            // Update cache
            await redisClient.set('clients', JSON.stringify(products));
            return products;
        }
    } catch (err) {
        console.log('Error in cache access:', err);
        throw err; // Rethrow to handle in calling function
    }
}

const getSpecifyProducts = async(categorie)=>{
  try {
        const cachedProducts = await redisClient.get(`p_${categorie}`);
        
        if (cachedProducts) {
        
            return JSON.parse(cachedProducts);
        } else {
        
            // Fetch from database
            const collection = db.collection(PRODUCTS_COLLECTION);
            const products = await collection.find({Categorie : categorie}).toArray();
            // Update cache
            await redisClient.set(`p_${categorie}`, JSON.stringify(products));
            return products;
        }
    } catch (err) {
        console.log('Error in cache access:', err);
        throw err; // Rethrow to handle in calling function
    }
}
const Getmakeups = async()=>{
  try {
        const cachedProducts = await redisClient.get(`p_Makeup`);
        
        if (cachedProducts) {
        
            return JSON.parse(cachedProducts);
        } else {
        
            // Fetch from database
            const collection = db.collection(PRODUCTS_COLLECTION);
            const products = [
      ...(await db.collection(PRODUCTS_COLLECTION).find({Categorie: 'makeup&parfum'}).toArray()),
      ...(await db.collection(PRODUCTS_COLLECTION).find({sous: 'parfum'}).toArray()),
      ...(await db.collection(PRODUCTS_COLLECTION).find({sous: 'maquillage'}).toArray())
    ];
            // Update cache
            await redisClient.set(`p_Makeup`, JSON.stringify(products));
            return products;
        }
    } catch (err) {
        console.log('Error in cache access:', err);
        throw err; // Rethrow to handle in calling function
    }
}
module.exports = {
    Getmakeups,
    getSpecifyProducts,
    saveProductsInCache,
    saveClientsCash,
    getClientsCash,
    getProductsCache
};