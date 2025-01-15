import passport from "passport";
import { setupJwtStrategy } from "../common/strategies/jwt.strategy"

const initialPassport =()=>{
    setupJwtStrategy(passport);
}

initialPassport()
export default passport;