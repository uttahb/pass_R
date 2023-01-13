import { shared, env } from "@appblocks/node-sdk";
import bcrypt from "bcrypt";

const BLOCK_NAME = "sample_password_recovery_fn";

const getFromBlockEnv = (name) => process.env[BLOCK_NAME.toLocaleUpperCase() + "_" + name];

const sample_password_recovery_fn = async (req, res) => {
  env.init();

  const saltRounds = getFromBlockEnv("SALT_ROUNDS") || 10;

  const { prisma, getBody, sendResponse, redis } = await shared.getShared();

  // health check
  if (req.params["health"] === "health") {
    sendResponse(res, 200, { success: true, msg: "Health check success" });
    return;
  }

  const { token, password, confirmPassword } = await getBody(req);
  console.log(`token:${token}`);
  console.log(`password:${password}`);
  console.log(`confirmPassword:${confirmPassword}`);

  if (password !== confirmPassword) {
    console.log("password mismatch");
    sendResponse(res, 200, {
      err: true,
      msg: "password mismatch",
      data: {},
    });
    return;
  }

  try {
    const [extractedToken, saltHash] = token.split("$");
    const salt = `$2b$${saltRounds}$${saltHash}`;
    console.log(`extractedToken:${extractedToken}`);
    console.log(`saltHash:${saltHash}`);
    console.log(`salt:${salt}`);
    const hash = await bcrypt.hash(extractedToken, salt);
    const tokenRedeemer = await redis.get(hash);
    if (!tokenRedeemer) {
      console.log(" token expired or invalidated");
      sendResponse(res, 200, {
        err: true,
        msg: "token expired",
        data: {},
      });
      return;
    }
    console.log("token valid");
    console.log(`token redeemed by email:${tokenRedeemer}`);

    const userData = await prisma.users.findFirst({ where: { email: tokenRedeemer } });
    if (!userData) {
      console.log(`redeemer email:${tokenRedeemer} doesn't exist in records`);
      throw err;
    }
    console.log(`redeemer email:${tokenRedeemer} exists in records`);

    const hashedPassword = await bcrypt.hash(password, saltRounds);
    console.log(`new password hashed`);
    await prisma.users.update({
      where: { email: tokenRedeemer },
      data: {
        password: hashedPassword,
      },
    });

    console.log(`record updated successfully `);
    sendResponse(res, 200, {
      err: false,
      msg: "updated successfullly",
      data: {},
    });
    return;
  } catch (err) {
    console.log(err);
    sendResponse(res, 500, {
      err: true,
      msg: "server error",
      data: {},
    });
    return;
  }
};

export default sample_password_recovery_fn;
