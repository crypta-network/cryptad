/**
 * This package provides classes to perform some random draws and statistical analysis.
 *
 * <p>The aim of this package is to provide the basic components needed to generate random variables
 * (correlated or not in the case of vectorial variables) that could be used in a simulation
 * application and to provide some basic statistical classes to analyze the simulation results.
 *
 * <p>At the lowest level, number generation one at a time for any primitive type is provided by
 * either the {@link org.spaceroots.mantissa.random.FourTapRandom FourTapRandom} class or the {@link
 * org.spaceroots.mantissa.random.MersenneTwister MersenneTwister} class which both extend the
 * <code>java.util.Random</code> standard class with much better algorithms. The {@link
 * org.spaceroots.mantissa.random.FourTapRandom FourTapRandom} algorithm is due to Robert M. Ziff
 * (Bill Maier kindly contributed this class to mantissa), whereas the {@link
 * org.spaceroots.mantissa.random.MersenneTwister MersenneTwister} class is due to Makoto Matsumoto
 * and Takuji Nishimura.
 *
 * <p>Vectorial generators are build by embedding a {@link
 * org.spaceroots.mantissa.random.NormalizedRandomGenerator normalized} scalar generator into the
 * vectorial generator classes {@link org.spaceroots.mantissa.random.CorrelatedRandomVectorGenerator
 * CorrelatedRandomVectorGenerator} or {@link
 * org.spaceroots.mantissa.random.UncorrelatedRandomVectorGenerator
 * UncorrelatedRandomVectorGenerator} that will be responsible for packaging all numbers into
 * vectors with the specified mean values, standard deviations, and correlation coefficients. Since
 * most practical problems make the assumption the probability distribution is gaussian, the
 * normalized generator will often be an instance of {@link
 * org.spaceroots.mantissa.random.GaussianRandomGenerator GaussianRandomGenerator}, but uniform
 * distribution is also available using instances of {@link
 * org.spaceroots.mantissa.random.UniformRandomGenerator UniformRandomGenerator}. <img
 * src="doc-files/org_spaceroots_mantissa_random_classes.png" />
 *
 * @author L. Maisonobe
 */
package org.spaceroots.mantissa.random;
