import * as PluginTypes from './PluginTypes';
import {Blockchains, BlockchainsArray} from '../models/Blockchains';
import Explorer from "../models/Explorer";

class PluginRepositorySingleton {

    constructor(){
        this.plugins = [];
    }

    loadPlugins(plugins){
        console.warn('loadPlugins PLUGINS:', this.plugins);
	    plugins.map(plugin => this.plugins.push(new plugin));
    }

    signatureProviders(){
        console.warn('signatureProviders PLUGINS:', this.plugins);
        return this.plugins.filter(plugin => plugin.type === PluginTypes.BLOCKCHAIN_SUPPORT);
    }

    plugin(name){
        console.warn('plugin PLUGINS:', name, this.plugins);
        return this.plugins.find(plugin => plugin.name === name);
    }

    defaultExplorers(){
        console.warn('defaultExplorers PLUGINS:', this.plugins);
        console.warn('defaultExplorers ARRAY:', BlockchainsArray);
        return BlockchainsArray.reduce((acc,x) => {
            if(this.plugin(x.value)) {
	            acc[x.value] = Explorer.fromJson({
                    raw:this.plugin(x.value).defaultExplorer()
                });
            }
            return acc;
        }, {})
    }

    bustCaches(){
        this.signatureProviders().map(sp => sp.bustCache())
    }
}

const PluginRepository = new PluginRepositorySingleton();
export default PluginRepository;
