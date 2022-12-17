package main

import (
	"context"
	"log"
	"os"
	"fmt"
	"bufio"
	"math/rand"
	"time"

	"go_mongo/pkg"


	"go.mongodb.org/mongo-driver/bson"
	// "go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"golang.org/x/crypto/bcrypt"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cache"
	"github.com/gofiber/fiber/v2/middleware/compress"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/etag"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/gofiber/fiber/v2/middleware/logger"

	"github.com/joho/godotenv"

	"github.com/jellydator/ttlcache/v2"

)

type MongoInstance struct {
	Client *mongo.Client
	Db     *mongo.Database
}

var mg MongoInstance
var trie *pkg.Trie
var keyCache ttlcache.SimpleCache = ttlcache.NewCache()

type User struct {
	ID     string  `json:"id,omitempty" bson:"_id,omitempty"`
	Email string  `json:"email"`
	Password string  `json:"password"`
	ApiKey string `json:"apikey"`
}

// Generate random 40 character string
func GenerateRandomString() string {
	var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_=+!@#$%&*")

	b := make([]rune, 40)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

// CheckPasswordHash compare password with hash
func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// Connect to MongoDB
func Connect(dbName string, mongoURI string) error {
	client, err := mongo.NewClient(options.Client().ApplyURI(mongoURI))

	if (err != nil) {
		log.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err = client.Connect(ctx)
	db := client.Database(dbName)

	if err != nil {
		return err
	}

	mg = MongoInstance{
		Client: client,
		Db:     db,
	}

	return nil
}

func buildTrie() error {
	readFile, err := os.Open("words.txt")

	if err != nil {
			fmt.Println(err)
			return nil
	}
	fileScanner := bufio.NewScanner(readFile)
	fileScanner.Split(bufio.ScanLines)
	var words []string

	for fileScanner.Scan() {
			words = append(words, fileScanner.Text())
	}

	readFile.Close()

	t := pkg.New().WithoutFuzzy().WithoutLevenshtein()
	t.Insert(words...)

	trie = t

	return nil
}

func main() {
	// Load .env file
	err := godotenv.Load()
	if err != nil {
		log.Println("Error loading .env file")
	}

	keyCache.SetTTL(time.Duration(30 * time.Second))

	dbName := os.Getenv("DATABASE")
	mongoURI := os.Getenv("MONGO_URI")
	// Connect to the database
	if err := Connect(dbName, mongoURI); err != nil {
		log.Fatal(err)
	}
	
	// Build trie
	if err := buildTrie(); err != nil {
		log.Fatal(err)
	} 

	// Create a Fiber app
	app := fiber.New()
	app.Use(cache.New())
	app.Use(compress.New(compress.Config{
			Level: compress.LevelBestSpeed, // 1
	}))
	app.Use(cors.New())
	app.Use(etag.New())
	app.Use(recover.New())
	app.Use(logger.New())
	// middleware to check for api key
	app.Use(func(c *fiber.Ctx) error {
		if c.Path() == "/login" || c.Path() == "/register" {
			return c.Next()
		}

		apiKey := c.Get("apikey")
		if apiKey == "" {
			return c.Status(500).JSON(fiber.Map{
				"message": "No api key provided",
			})
		}

		_, err := keyCache.Get(apiKey)

		if err != nil {
			user := c.Get("user")
			if user == "" {
				return c.Status(500).JSON(fiber.Map{
					"message": "No user provided",
				})
			}

			collection := mg.Db.Collection("users")
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			var result User
			query := bson.M{"apikey": apiKey, "email": user}
			err := collection.FindOne(ctx, query).Decode(&result)
			if err != nil {
				return c.Status(500).JSON(fiber.Map{
					"message": "Invalid api key",
				})
			}
		}
		keyCache.Set(apiKey, true)

		return c.Next()
	})

	app.Post("/login" , func(c *fiber.Ctx) error {
		var user User
		if err := c.BodyParser(&user); err != nil {
			return err
		}
		
		collection := mg.Db.Collection("users")
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		var result User
		query := bson.M{"email": user.Email}
		err := collection.FindOne(ctx, query).Decode(&result)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{
				"message": "User not found",
			})
		}

		if !CheckPasswordHash(user.Password, result.Password) {
			return c.Status(500).JSON(fiber.Map{
				"message": "Wrong password",
			})
		}

		return c.JSON(fiber.Map{
			"message": "User logged in",
			"apikey": result.ApiKey,
		})
	})

	app.Post("/register" , func(c *fiber.Ctx) error {
		var user User
		if err := c.BodyParser(&user); err != nil {
			return err
		}
		
		collection := mg.Db.Collection("users")
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		
		hash, err := bcrypt.GenerateFromPassword([]byte(user.Password), 10)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{
				"message": "Error hashing password",
			})
		}

		user.Password = string(hash)
		user.ApiKey = GenerateRandomString()
		_, err = collection.InsertOne(ctx, user)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{
				"message": "Error inserting user",
			})
		}

		return c.JSON(fiber.Map{
			"message": "User registered",
			"apiKey": user.ApiKey,
		})
	})

	app.Get("/suggest/:word" , func(c *fiber.Ctx) error {
		word := c.Params("word")
		return c.JSON(trie.SearchAll(word))
	})

	log.Fatal(app.Listen(":8080"))
}
