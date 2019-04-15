import { NappJSService } from "nappjs";
export default class NappJSJWT extends NappJSService {
    getToken(req: any): Promise<any>;
    checkJWTPermissions(req: any, resource: any): Promise<Boolean>;
    private isEnabled;
    private getConfigs;
}
