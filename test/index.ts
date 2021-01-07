
import * as Jwt from '..';
import { Plugin } from '@hapi/hapi';
import * as Lab from '@hapi/lab';

const { expect } = Lab.types;

// Jwt

expect.type<Plugin<void>>(Jwt);
