import { Hono } from "hono";
import { cors } from "hono/cors";
import { PrismaClient, Prisma } from "@prisma/client";
import { HTTPException } from "hono/http-exception";
import { sign } from "hono/jwt";
import axios from "axios";
import { jwt } from "hono/jwt";
import { hash, compare } from "bcrypt";

const app = new Hono();
const prisma = new PrismaClient();

app.use("/*", cors());

app.use(
  "/protected/*",
  jwt({
    secret: "mySecretKey",
  })
);

// Register endpoint
app.post("/register", async (ctx) => {
  const { email, password } = await ctx.req.json();
  const hashedPassword = await hash(password, 4);

  try {
    const user = await prisma.user.create({
      data: {
        email,
        hashedPassword,
      },
    });
    return ctx.json({ message: `${user.email} created successfully` });
  } catch (e) {
    if (e instanceof Prisma.PrismaClientKnownRequestError && e.code === "P2002") {
      return ctx.json({ message: "Email already exists" });
    }
    throw new HTTPException(500, { message: "Internal Server Error" });
  }
});

// Login endpoint
app.post("/login", async (ctx) => {
  try {
    const { email, password } = await ctx.req.json();
    const user = await prisma.user.findUnique({
      where: { email },
      select: { id: true, hashedPassword: true },
    });

    if (!user) {
      return ctx.json({ message: "User not found" }, 404);
    }

    const match = await compare(password, user.hashedPassword);

    if (match) {
      const payload = {
        sub: user.id,
        exp: Math.floor(Date.now() / 1000) + 60 * 60, // Token expires in 60 minutes
      };
      const secret = "mySecretKey";
      const token = await sign(payload, secret);

      if (typeof token !== "string") {
        console.error("Token signing failed", token);
        throw new HTTPException(500, { message: "Token signing failed" });
      }

      return ctx.json({ message: "Login successful", token });
    } else {
      throw new HTTPException(401, { message: "Invalid credentials" });
    }
  } catch (error) {
    console.error("Login error:", error);
    if (error instanceof HTTPException) {
      throw error;
    } else {
      throw new HTTPException(500, { message: "Internal Server Error" });
    }
  }
});

// Retrieve Pokémon endpoint
app.get("/pokemon/:name", async (ctx) => {
  const { name } = ctx.req.param();

  try {
    const response = await axios.get(`https://pokeapi.co/api/v2/pokemon/${name}`);
    return ctx.json({ data: response.data });
  } catch (error) {
    if (axios.isAxiosError(error)) {
      if (error.response && error.response.status === 404) {
        return ctx.json({ message: "Your Pokémon was not found!" }, 404);
      }
      return ctx.json({ message: "An error occurred while fetching the Pokémon data" }, 500);
    } else {
      return ctx.json({ message: "An unexpected error occurred" }, 500);
    }
  }
});

// Catch Pokémon endpoint
app.post("/protected/catch", async (ctx) => {
  try {
    const payload = ctx.get("jwtPayload");
    if (!payload) {
      throw new HTTPException(401, { message: "YOU ARE UNAUTHORIZED" });
    }

    const { name: pokemonName } = await ctx.req.json();

    if (!pokemonName) {
      throw new HTTPException(400, { message: "Pokemon name is required" });
    }

    let pokemon = await prisma.pokemon.findUnique({
      where: { name: pokemonName },
    });

    if (!pokemon) {
      pokemon = await prisma.pokemon.create({
        data: { name: pokemonName },
      });
    }

    const caughtPokemon = await prisma.caughtPokemon.create({
      data: {
        userId: payload.sub,
        pokemonId: pokemon.id,
      },
    });

    return ctx.json({ message: "Pokemon caught", data: caughtPokemon });
  } catch (error) {
    console.error(error);
    if (error instanceof HTTPException) {
      throw error;
    } else {
      throw new HTTPException(500, { message: "Internal Server Error" });
    }
  }
});

// Release Pokémon endpoint
app.delete("/protected/release/:id", async (ctx) => {
  const payload = ctx.get("jwtPayload");
  if (!payload) {
    throw new HTTPException(401, { message: "YOU ARE UNAUTHORIZED" });
  }

  const { id } = ctx.req.param();

  try {
    const deleteResult = await prisma.caughtPokemon.deleteMany({
      where: { id, userId: payload.sub },
    });

    if (deleteResult.count === 0) {
      return ctx.json({ message: "Pokemon not found or not owned by user" }, 404);
    }

    return ctx.json({ message: "Pokemon is released" });
  } catch (error) {
    return ctx.json({ message: "An error occurred while releasing the Pokemon" }, 500);
  }
});

// Get caught Pokémon endpoint
app.get("/protected/caught", async (ctx) => {
  const payload = ctx.get("jwtPayload");
  if (!payload) {
    throw new HTTPException(401, { message: "YOU ARE UNAUTHORIZED" });
  }

  try {
    const caughtPokemon = await prisma.caughtPokemon.findMany({
      where: { userId: payload.sub },
      include: { pokemon: true },
    });

    if (!caughtPokemon.length) {
      return ctx.json({ message: "No Pokémon found." });
    }

    return ctx.json({ data: caughtPokemon });
  } catch (error) {
    console.error("Error fetching caught Pokémon:", error);
    return ctx.json({ message: "An error occurred while fetching caught Pokémon" }, 500);
  }
});

export default app;
