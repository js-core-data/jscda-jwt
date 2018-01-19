import { NappJSService } from 'nappjs';
export declare class NappJSJWT extends NappJSService {
    getToken(req: any): Promise<any>;
    checkJWTPermissions(req: any, resource: any): Promise<boolean>;
}
