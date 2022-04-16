import UnichainJS from 'index';
import utils from 'utils';
import semver from 'semver';

export default class Plugin {

    constructor(unichainJS = false, options = {}) {
        if (!unichainJS || !unichainJS instanceof UnichainJS)
            throw new Error('Expected instance of UnichainJS');
        this.unichainJS = unichainJS;
        this.pluginNoOverride = ['register'];
        this.disablePlugins = options.disablePlugins;
    }

    register(Plugin, options) {
        let pluginInterface = {
            requires: '0.0.0',
            components: {}
        }
        let result = {
            libs: [],
            plugged: [],
            skipped: []
        }
        if (this.disablePlugins) {
            result.error = 'This instance of UnichainJS has plugins disabled.'
            return result;
        }
        const plugin = new Plugin(this.unichainJS)
        if (utils.isFunction(plugin.pluginInterface)) {
            pluginInterface = plugin.pluginInterface(options)
        }
        if (semver.satisfies(UnichainJS.version, pluginInterface.requires)) {
            if (pluginInterface.fullClass) {
                // plug the entire class at the same level of unichainJS.api
                let className = plugin.constructor.name
                let classInstanceName = className.substring(0, 1).toLowerCase() + className.substring(1)
                if (className !== classInstanceName) {
                    UnichainJS[className] = Plugin
                    this.unichainJS[classInstanceName] = plugin
                    result.libs.push(className)
                }
            } else {
                // plug methods into a class, like api
                for (let component in pluginInterface.components) {
                    if (!this.unichainJS.hasOwnProperty(component)) {
                        continue
                    }
                    let methods = pluginInterface.components[component]
                    let pluginNoOverride = this.unichainJS[component].pluginNoOverride || []
                    for (let method in methods) {
                        if (method === 'constructor' || (this.unichainJS[component][method] &&
                            (pluginNoOverride.includes(method) // blacklisted methods
                                || /^_/.test(method)) // private methods
                        )) {
                            result.skipped.push(method)
                            continue
                        }
                        this.unichainJS[component][method] = methods[method].bind(this.unichainJS[component])
                        result.plugged.push(method)
                    }
                }
            }
        } else {
            throw new Error('The plugin is not compatible with this version of UnichainJS')
        }
        return result
    }
}

